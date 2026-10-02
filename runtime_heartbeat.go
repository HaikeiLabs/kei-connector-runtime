package connectorruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/policybundlehealth"
	"github.com/google/uuid"
)

// Heartbeat exit codes. They are part of the `runtime heartbeat --output jsonl`
// contract a supervising SDK (Agentware RuntimeLink) maps to link state. Legacy
// text mode keeps exiting 1 on every failure.
const (
	heartbeatExitOK           = 0 // graceful: stdin EOF, SIGTERM, or cancellation
	heartbeatExitTransient    = 1 // transient or internal; the supervisor restarts with backoff
	heartbeatExitContract     = 2 // usage error, catalog 400, or malformed catalog response
	heartbeatExitUnauthorized = 3 // unknown, revoked, or inactive installation
	heartbeatExitConfig       = 4 // invalid runtime configuration
)

// HeartbeatOutcome is the closed set of results for one runtime -> catalog
// heartbeat. The catalog_* values locate a failure in the runtime -> catalog
// leg, so a supervisor can tell them apart from a runtime that is itself down.
type HeartbeatOutcome string

const (
	HeartbeatOK                  HeartbeatOutcome = "ok"
	HeartbeatCatalogUnreachable  HeartbeatOutcome = "catalog_unreachable"
	HeartbeatCatalogTimeout      HeartbeatOutcome = "catalog_timeout"
	HeartbeatCatalogError        HeartbeatOutcome = "catalog_error"
	HeartbeatCatalogBackpressure HeartbeatOutcome = "catalog_backpressure"
	HeartbeatCatalogRejected     HeartbeatOutcome = "catalog_rejected"
	HeartbeatUnauthorized        HeartbeatOutcome = "unauthorized"
)

// transient reports whether the outcome may clear on its own, so the loop
// retries it instead of exiting.
func (o HeartbeatOutcome) transient() bool {
	switch o {
	case HeartbeatCatalogUnreachable, HeartbeatCatalogTimeout, HeartbeatCatalogError, HeartbeatCatalogBackpressure:
		return true
	}
	return false
}

// retryableInTick reports whether a failure earns the one in-tick retry. A 429
// does not: the catalog asked for less traffic, so the next tick waits instead.
func retryableInTick(o HeartbeatOutcome) bool {
	return o.transient() && o != HeartbeatCatalogBackpressure
}

// HeartbeatFailure is a classified heartbeat error. It carries no token or
// request body, only the outcome, status, and the catalog's Retry-After hint.
type HeartbeatFailure struct {
	Outcome    HeartbeatOutcome
	StatusCode int
	RetryAfter time.Duration
	Wrapped    error
}

func (f *HeartbeatFailure) Error() string { return f.Wrapped.Error() }
func (f *HeartbeatFailure) Unwrap() error { return f.Wrapped }

func classifyHeartbeatStatus(status int) HeartbeatOutcome {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return HeartbeatUnauthorized
	case status == http.StatusTooManyRequests:
		return HeartbeatCatalogBackpressure
	case status >= 500:
		return HeartbeatCatalogError
	case status >= 400:
		return HeartbeatCatalogRejected
	default:
		// A 2xx other than 204, or a redirect, is not the contract but is not
		// proof the request was wrong either; retry it like a catalog fault.
		return HeartbeatCatalogError
	}
}

func classifyTransportError(err error) HeartbeatOutcome {
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return HeartbeatCatalogTimeout
	}
	return HeartbeatCatalogUnreachable
}

// classifyHeartbeatError maps any client error onto an outcome. An
// unclassified error is treated as unreachable so it is retried, not fatal.
func classifyHeartbeatError(err error) *HeartbeatFailure {
	var failure *HeartbeatFailure
	if errors.As(err, &failure) {
		return failure
	}
	return &HeartbeatFailure{Outcome: HeartbeatCatalogUnreachable, Wrapped: err}
}

// parseRetryAfter reads delay-seconds or an HTTP date. Anything else is zero.
func parseRetryAfter(value string, now time.Time) time.Duration {
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds < 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil && at.After(now) {
		return at.Sub(now)
	}
	return 0
}

// HeartbeatReport is the POST /api/v1/runtime/heartbeat body. A report with
// only RuntimeVersion is the v1 body every catalog accepts. The v2 fields are
// declared, non-authoritative labels and counters: installation, org, and
// workspace identity come only from the bearer token, so the report has no
// field that could carry them, a credential, or any provider data.
type HeartbeatReport struct {
	RuntimeVersion   string                     `json:"runtime_version"`
	SchemaVersion    int                        `json:"schema_version,omitempty"`
	RunID            string                     `json:"run_id,omitempty"`
	Seq              uint64                     `json:"seq,omitempty"`
	IntervalSeconds  int                        `json:"interval_seconds,omitempty"`
	RuntimeStartedAt string                     `json:"runtime_started_at,omitempty"`
	Harness          *HarnessEnvelope           `json:"harness,omitempty"`
	Counters         *HeartbeatCounter          `json:"counters,omitempty"`
	ToolSyncStatus   string                     `json:"tool_sync_status,omitempty"`
	PolicyBundle     *policybundlehealth.Health `json:"policy_bundle,omitempty"`
}

type HeartbeatCounter struct {
	BeatsFailedSinceOK int `json:"beats_failed_since_ok"`
}

// HarnessEnvelope is the declared harness metadata a supervising SDK passes to
// the runtime. It labels heartbeats for attribution and is never used for
// authorization.
type HarnessEnvelope struct {
	Kind          string `json:"kind,omitempty"`
	Version       string `json:"version,omitempty"`
	DeploymentEnv string `json:"deployment_env,omitempty"`
	SDKLang       string `json:"sdk_lang,omitempty"`
	SDKVersion    string `json:"sdk_version,omitempty"`
	Link          string `json:"link,omitempty"`
}

var (
	harnessKinds    = map[string]bool{"assistant": true, "pde": true, "chat-discord": true, "chat-slack": true, "chat-teams": true, "cli": true}
	harnessSDKLangs = map[string]bool{"go": true, "python": true, "typescript": true}
	envelopeVersion = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)
	envelopeEnv     = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,32}$`)
	envelopeRunID   = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
)

// errEnvelopeInvalid names the offending variable but never echoes its value,
// in case a secret was put in the wrong variable.
type errEnvelopeInvalid struct{ name string }

func (e errEnvelopeInvalid) Error() string { return e.name + " is not a valid value" }

// harnessEnvelopeFromEnv reads exactly the allowlisted envelope variables. No
// other environment value can reach the heartbeat body. It returns nil when no
// envelope variable is set.
func harnessEnvelopeFromEnv(getenv func(string) string) (*HarnessEnvelope, error) {
	envelope := HarnessEnvelope{
		Kind:          getenv("KEI_HARNESS_KIND"),
		Version:       getenv("KEI_HARNESS_VERSION"),
		DeploymentEnv: getenv("KEI_DEPLOYMENT_ENV"),
		SDKLang:       getenv("KEI_AGENTWARE_SDK_LANG"),
		SDKVersion:    getenv("KEI_AGENTWARE_SDK_VERSION"),
	}
	checks := []struct {
		name, value string
		valid       func(string) bool
	}{
		{"KEI_HARNESS_KIND", envelope.Kind, func(v string) bool { return harnessKinds[v] }},
		{"KEI_HARNESS_VERSION", envelope.Version, envelopeVersion.MatchString},
		{"KEI_DEPLOYMENT_ENV", envelope.DeploymentEnv, envelopeEnv.MatchString},
		{"KEI_AGENTWARE_SDK_LANG", envelope.SDKLang, func(v string) bool { return harnessSDKLangs[v] }},
		{"KEI_AGENTWARE_SDK_VERSION", envelope.SDKVersion, envelopeVersion.MatchString},
	}
	for _, check := range checks {
		if check.value != "" && !check.valid(check.value) {
			return nil, errEnvelopeInvalid{name: check.name}
		}
	}
	if envelope == (HarnessEnvelope{}) {
		return nil, nil
	}
	return &envelope, nil
}

// heartbeatRunID uses the supervisor's run id when it supplies a valid one so
// SDK, runtime, and catalog records join; otherwise it generates one.
func heartbeatRunID(getenv func(string) string) (string, error) {
	if runID := getenv("KEI_HEARTBEAT_RUN_ID"); runID != "" {
		if !envelopeRunID.MatchString(runID) {
			return "", errEnvelopeInvalid{name: "KEI_HEARTBEAT_RUN_ID"}
		}
		return runID, nil
	}
	return uuid.NewString(), nil
}

// heartbeatEvent is one `--output jsonl` stdout line. The schema is closed:
// identity fields come from whoami, and nothing else carries free text, so an
// error string, token, or provider payload cannot reach stdout.
type heartbeatEvent struct {
	V              int              `json:"v"`
	Event          string           `json:"event"`
	RunID          string           `json:"run_id"`
	InstallationID string           `json:"installation_id,omitempty"`
	OrgID          string           `json:"org_id,omitempty"`
	WorkspaceID    *string          `json:"workspace_id,omitempty"`
	Platform       string           `json:"platform,omitempty"`
	Status         string           `json:"status,omitempty"`
	BindingStatus  string           `json:"binding_status,omitempty"`
	RuntimeVersion string           `json:"runtime_version,omitempty"`
	AgentID        string           `json:"agent_id,omitempty"`
	Agents         []heartbeatAgent `json:"agents,omitempty"`
	// AgentsTruncated reports that Agents was cut to fit one stdout line. The
	// default assignment is always kept.
	AgentsTruncated bool             `json:"agents_truncated,omitempty"`
	Seq             *uint64          `json:"seq,omitempty"`
	At              string           `json:"at,omitempty"`
	Outcome         HeartbeatOutcome `json:"outcome,omitempty"`
	HTTPStatus      int              `json:"http_status,omitempty"`
	LatencyMS       *int64           `json:"latency_ms,omitempty"`
	NextInMS        *int64           `json:"next_in_ms,omitempty"`
	Reason          string           `json:"reason,omitempty"`
}

// heartbeatAgent is one whoami agent assignment on the identity event.
type heartbeatAgent struct {
	AgentID   string `json:"agent_id"`
	IsDefault bool   `json:"is_default"`
}

// Terminal reasons, beyond the outcomes unauthorized and catalog_rejected.
const (
	heartbeatReasonConfigInvalid    = "config_invalid"
	heartbeatReasonContractMismatch = "contract_mismatch"
)

// maxHeartbeatEventBytes bounds one stdout line for the supervisor's reader.
const maxHeartbeatEventBytes = 4 << 10

type heartbeatEmitter struct {
	mu    sync.Mutex
	out   io.Writer
	runID string
}

func (e *heartbeatEmitter) emit(event heartbeatEvent) {
	if e == nil {
		return
	}
	event.V = 1
	event.RunID = e.runID
	line, err := json.Marshal(event)
	if err != nil || len(line) >= maxHeartbeatEventBytes {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	_, _ = e.out.Write(append(line, '\n'))
}

func (e *heartbeatEmitter) identity(identity *RuntimeIdentity) {
	event := heartbeatEvent{
		Event:          "identity",
		InstallationID: identity.ID,
		OrgID:          identity.OrgID,
		WorkspaceID:    identity.WorkspaceID,
		Platform:       identity.Platform,
		Status:         identity.Status,
		BindingStatus:  identity.BindingStatus,
		RuntimeVersion: version,
		AgentID:        identity.AgentID,
	}
	for _, agent := range identity.Agents {
		if agent.AgentID == "" {
			continue
		}
		event.Agents = append(event.Agents, heartbeatAgent{AgentID: agent.AgentID, IsDefault: agent.IsDefault})
		if event.AgentID == "" && agent.IsDefault {
			event.AgentID = agent.AgentID
		}
	}
	if e != nil {
		event.Agents, event.AgentsTruncated = e.fitIdentityAgents(event)
	}
	e.emit(event)
}

// fitIdentityAgents keeps the identity event under maxHeartbeatEventBytes. When
// the full agent list does not fit, it keeps the default assignment and then
// as many others as fit, in whoami order, and marks the list truncated.
func (e *heartbeatEmitter) fitIdentityAgents(event heartbeatEvent) ([]heartbeatAgent, bool) {
	agents := event.Agents
	event.V, event.RunID = 1, e.runID
	if size, err := encodedLen(event); err != nil || size < maxHeartbeatEventBytes {
		return agents, false
	}
	keep := make([]bool, len(agents))
	event.AgentsTruncated = true
	event.Agents = nil
	for i, agent := range agents {
		if agent.IsDefault || agent.AgentID == event.AgentID {
			keep[i] = true
			event.Agents = append(event.Agents, agent)
		}
	}
	size, err := encodedLen(event)
	if err != nil || size >= maxHeartbeatEventBytes {
		return nil, true
	}
	for i, agent := range agents {
		if keep[i] {
			continue
		}
		entry, err := encodedLen(agent)
		if err != nil {
			continue
		}
		// One separating comma, or "[]" becoming the first entry's brackets
		// when no default was kept.
		grow := entry + 1
		if len(event.Agents) == 0 {
			grow = len(`"agents":[],`) + entry
		}
		if size+grow >= maxHeartbeatEventBytes {
			break
		}
		size += grow
		keep[i] = true
		event.Agents = append(event.Agents, agent)
	}
	kept := make([]heartbeatAgent, 0, len(event.Agents))
	for i, agent := range agents {
		if keep[i] {
			kept = append(kept, agent)
		}
	}
	return kept, true
}

func encodedLen(v any) (int, error) {
	line, err := json.Marshal(v)
	return len(line), err
}

func (e *heartbeatEmitter) terminal(reason string) {
	e.emit(heartbeatEvent{Event: "terminal", Reason: reason})
}

// heartbeatLoop reports runtime -> catalog liveness until its context ends or
// the catalog rejects the installation. Transient catalog failures are retried
// once within the tick and then reported; they never stop the loop.
type heartbeatLoop struct {
	client    RuntimeClient
	token     string
	report    HeartbeatReport // template; v1 when only RuntimeVersion is set
	versioned bool            // send the v2 body fields
	interval  time.Duration
	events    *heartbeatEmitter // nil in legacy text mode
	warn      io.Writer         // legacy text mode diagnostics; outcome only
	now       func() time.Time
	jitter    func(time.Duration) time.Duration

	seq           uint64
	failedSinceOK int
	lastAt        time.Time
	lastLatency   time.Duration

	// appendLifecycle writes a lifecycle audit record to the local spool after
	// each tick, when set. nil in tests and when no audit path is configured.
	appendLifecycle func(LifecycleEvent) error
	policyBundle    func() *policybundlehealth.Health
}

func (l *heartbeatLoop) retryDelay() time.Duration {
	return min(5*time.Second, l.interval/4)
}

// maxBackpressure caps how long a catalog Retry-After can stretch one tick.
func (l *heartbeatLoop) maxBackpressure() time.Duration {
	return 5 * l.interval
}

// run sends the first beat immediately when immediate is set, then one beat
// per jittered interval. It returns nil when ctx ends and a *HeartbeatFailure
// when the catalog rejects the runtime.
func (l *heartbeatLoop) run(ctx context.Context, immediate bool) error {
	wait := l.jitter(l.interval)
	if immediate {
		wait = 0
	}
	for {
		if !sleepContext(ctx, wait) {
			return nil
		}
		failure := l.tick(ctx)
		if ctx.Err() != nil {
			return nil
		}
		wait = l.jitter(l.interval)
		if failure != nil && failure.Outcome == HeartbeatCatalogBackpressure {
			wait = max(wait, min(failure.RetryAfter, l.maxBackpressure()))
		}
		l.record(failure, wait)
		if failure != nil && !failure.Outcome.transient() {
			return failure
		}
	}
}

// tick sends one heartbeat, retrying a transient failure once. A 429 is not
// retried in-tick; the next tick is delayed by Retry-After instead.
func (l *heartbeatLoop) tick(ctx context.Context) *HeartbeatFailure {
	l.seq++
	started := l.now()
	failure := l.send(ctx)
	if failure != nil && retryableInTick(failure.Outcome) {
		if !sleepContext(ctx, l.retryDelay()) {
			return nil
		}
		failure = l.send(ctx)
	}
	l.lastLatency = l.now().Sub(started)
	l.lastAt = started
	return failure
}

func (l *heartbeatLoop) send(ctx context.Context) *HeartbeatFailure {
	report := l.report
	if l.policyBundle != nil {
		report.PolicyBundle = l.policyBundle()
	}
	if l.versioned {
		report.Seq = l.seq
		report.Counters = &HeartbeatCounter{BeatsFailedSinceOK: l.failedSinceOK}
	}
	if err := l.client.Heartbeat(ctx, l.token, report); err != nil {
		return classifyHeartbeatError(err)
	}
	return nil
}

func (l *heartbeatLoop) record(failure *HeartbeatFailure, next time.Duration) {
	outcome, status := HeartbeatOK, 0
	if failure != nil {
		outcome, status = failure.Outcome, failure.StatusCode
		l.failedSinceOK++
	} else {
		l.failedSinceOK = 0
	}
	if l.events != nil {
		seq, latency, nextMS := l.seq, l.lastLatency.Milliseconds(), next.Milliseconds()
		l.events.emit(heartbeatEvent{
			Event:      "beat",
			Seq:        &seq,
			At:         l.lastAt.UTC().Format(time.RFC3339),
			Outcome:    outcome,
			HTTPStatus: status,
			LatencyMS:  &latency,
			NextInMS:   &nextMS,
		})
	} else if failure != nil && l.warn != nil && failure.Outcome.transient() {
		fmt.Fprintf(l.warn, "runtime heartbeat: %s; retrying in %s\n", failure.Outcome, next.Round(time.Second))
	}
	l.emitLifecycleRecord(outcome)
}

// emitLifecycleRecord writes one lifecycle audit record for the latest tick.
func (l *heartbeatLoop) emitLifecycleRecord(outcome HeartbeatOutcome) {
	if l.appendLifecycle == nil {
		return
	}
	_ = l.appendLifecycle(LifecycleEvent{
		EventClass:     eventClassLifecycle,
		SchemaVersion:  1,
		EventType:      "heartbeat",
		Outcome:        outcome,
		ObservedAt:     l.lastAt.UTC(),
		RuntimeVersion: l.report.RuntimeVersion,
		RunID:          l.report.RunID,
		Seq:            l.seq,
	})
}

// jitterInterval spreads ticks across interval ±10% so a fleet restarted
// together does not heartbeat in lockstep.
func jitterInterval(interval time.Duration) time.Duration {
	spread := int64(interval / 10)
	if spread <= 0 {
		return interval
	}
	return interval + time.Duration(rand.Int64N(2*spread+1)-spread)
}

// sleepContext waits d, returning false if ctx ends first.
func sleepContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// watchParentStdin cancels the returned context when stdin reaches EOF. A
// supervisor holds the pipe open for its lifetime, so EOF means the parent is
// gone and the runtime must stop reporting a dead harness as live.
func watchParentStdin(ctx context.Context, stdin io.Reader) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		_, _ = io.Copy(io.Discard, stdin)
		cancel()
	}()
	return ctx, cancel
}
