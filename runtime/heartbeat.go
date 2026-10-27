package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"regexp"
	"sync"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/policybundlehealth"
	"github.com/google/uuid"
)

// Terminal reasons, beyond the outcomes unauthorized and catalog_rejected.
const (
	ReasonConfigInvalid    = "config_invalid"
	ReasonContractMismatch = "contract_mismatch"
)

// maxHeartbeatEventBytes bounds one stdout line for the supervisor's reader.
const maxHeartbeatEventBytes = 4 << 10

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

// HeartbeatEvent is one `--output jsonl` stdout line. The schema is closed:
// identity fields come from whoami, and nothing else carries free text, so an
// error string, token, or provider payload cannot reach stdout.
type HeartbeatEvent struct {
	V               int              `json:"v"`
	Event           string           `json:"event"`
	RunID           string           `json:"run_id"`
	InstallationID  string           `json:"installation_id,omitempty"`
	OrgID           string           `json:"org_id,omitempty"`
	WorkspaceID     *string          `json:"workspace_id,omitempty"`
	Platform        string           `json:"platform,omitempty"`
	Status          string           `json:"status,omitempty"`
	BindingStatus   string           `json:"binding_status,omitempty"`
	RuntimeVersion  string           `json:"runtime_version,omitempty"`
	AgentID         string           `json:"agent_id,omitempty"`
	Agents          []HeartbeatAgent `json:"agents,omitempty"`
	AgentsTruncated bool             `json:"agents_truncated,omitempty"`
	Seq             *uint64          `json:"seq,omitempty"`
	At              string           `json:"at,omitempty"`
	Outcome         HeartbeatOutcome `json:"outcome,omitempty"`
	HTTPStatus      int              `json:"http_status,omitempty"`
	LatencyMS       *int64           `json:"latency_ms,omitempty"`
	NextInMS        *int64           `json:"next_in_ms,omitempty"`
	Reason          string           `json:"reason,omitempty"`
}

// HeartbeatEmitter writes heartbeat stdout events. It is safe for concurrent
// use. Created via NewHeartbeatEmitter.
type HeartbeatEmitter struct {
	mu    sync.Mutex
	out   io.Writer
	runID string
}

func NewHeartbeatEmitter(out io.Writer, runID string) *HeartbeatEmitter {
	return &HeartbeatEmitter{out: out, runID: runID}
}

func (e *HeartbeatEmitter) Emit(event HeartbeatEvent) {
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

func (e *HeartbeatEmitter) Identity(identity *HeartbeatIdentity, runtimeVersion string) {
	event := HeartbeatEvent{
		Event:          "identity",
		InstallationID: identity.ID,
		OrgID:          identity.OrgID,
		WorkspaceID:    identity.WorkspaceID,
		Platform:       identity.Platform,
		Status:         identity.Status,
		BindingStatus:  identity.BindingStatus,
		RuntimeVersion: runtimeVersion,
		AgentID:        identity.AgentID,
	}
	for _, agent := range identity.Agents {
		if agent.AgentID == "" {
			continue
		}
		event.Agents = append(event.Agents, HeartbeatAgent{AgentID: agent.AgentID, IsDefault: agent.IsDefault})
		if event.AgentID == "" && agent.IsDefault {
			event.AgentID = agent.AgentID
		}
	}
	if e != nil {
		event.Agents, event.AgentsTruncated = e.fitIdentityAgents(event)
	}
	e.Emit(event)
}

// fitIdentityAgents keeps the identity event under maxHeartbeatEventBytes. When
// the full agent list does not fit, it keeps the default assignment and then
// as many others as fit, in whoami order, and marks the list truncated.
func (e *HeartbeatEmitter) fitIdentityAgents(event HeartbeatEvent) ([]HeartbeatAgent, bool) {
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
	kept := make([]HeartbeatAgent, 0, len(event.Agents))
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

func (e *HeartbeatEmitter) Terminal(reason string) {
	e.Emit(HeartbeatEvent{Event: "terminal", Reason: reason})
}

// ClassifyHeartbeatError maps any client error onto an outcome. An
// unclassified error is treated as unreachable so it is retried, not fatal.
func ClassifyHeartbeatError(err error) *HeartbeatFailure {
	var failure *HeartbeatFailure
	if errors.As(err, &failure) {
		return failure
	}
	return &HeartbeatFailure{Outcome: HeartbeatCatalogUnreachable, Wrapped: err}
}

// HeartbeatRunID uses the supervisor's run id when it supplies a valid one so
// SDK, runtime, and catalog records join; otherwise it generates one.
func HeartbeatRunID(getenv func(string) string) (string, error) {
	if runID := getenv("KEI_HEARTBEAT_RUN_ID"); runID != "" {
		if !envelopeRunID.MatchString(runID) {
			return "", errEnvelopeInvalid{name: "KEI_HEARTBEAT_RUN_ID"}
		}
		return runID, nil
	}
	return uuid.NewString(), nil
}

// HarnessEnvelopeFromEnv reads exactly the allowlisted envelope variables. No
// other environment value can reach the heartbeat body. It returns nil when no
// envelope variable is set.
func HarnessEnvelopeFromEnv(getenv func(string) string) (*HarnessEnvelope, error) {
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

// JitterInterval spreads d by ±10 %.
func JitterInterval(interval time.Duration) time.Duration {
	spread := int64(interval / 10)
	if spread <= 0 {
		return interval
	}
	return interval + time.Duration(rand.Int64N(2*spread+1)-spread)
}

// WatchParentStdin cancels the returned context when stdin reaches EOF. A
// supervisor holds the pipe open for its lifetime, so EOF means the parent is
// gone and the runtime must stop reporting a dead harness as live.
func WatchParentStdin(ctx context.Context, stdin io.Reader) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		_, _ = io.Copy(io.Discard, stdin)
		cancel()
	}()
	return ctx, cancel
}

// SleepContext waits d, returning false if ctx ends first.
func SleepContext(ctx context.Context, d time.Duration) bool {
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

// HeartbeatLoop reports runtime → catalog liveness until its context ends or
// the catalog rejects the installation. Transient catalog failures are retried
// once within the tick and then reported; they never stop the loop.
type HeartbeatLoop struct {
	Client    HeartbeatClient
	Token     string
	Report    HeartbeatReport
	Versioned bool
	Interval  time.Duration
	Events    *HeartbeatEmitter
	Warn      io.Writer
	Now       func() time.Time
	Jitter    func(time.Duration) time.Duration

	seq           uint64
	failedSinceOK int
	lastAt        time.Time
	lastLatency   time.Duration

	AppendLifecycle func(LifecycleEvent) error
	PolicyBundle    func() *policybundlehealth.Health

	// ConnectorActivations supplies the connector ids whose external
	// credential_ref this runtime has resolved through credential sync. The
	// loop reports the ids still owed a report on the next beat, keeps them
	// queued across failed beats, and stops re-reporting an id once a beat
	// carrying it succeeds. It is nil when the loop has nothing to report.
	ConnectorActivations func() ([]string, error)

	reportedActivations map[string]bool
}

func (l *HeartbeatLoop) retryDelay() time.Duration {
	return min(5*time.Second, l.Interval/4)
}

func (l *HeartbeatLoop) maxBackpressure() time.Duration {
	return 5 * l.Interval
}

// Run sends the first beat immediately when immediate is set, then one beat
// per jittered interval. It returns nil when ctx ends and a *HeartbeatFailure
// when the catalog rejects the runtime.
func (l *HeartbeatLoop) Run(ctx context.Context, immediate bool) error {
	wait := l.Jitter(l.Interval)
	if immediate {
		wait = 0
	}
	for {
		if !SleepContext(ctx, wait) {
			return nil
		}
		failure := l.Tick(ctx)
		if ctx.Err() != nil {
			return nil
		}
		wait = l.Jitter(l.Interval)
		if failure != nil && failure.Outcome == HeartbeatCatalogBackpressure {
			wait = max(wait, min(failure.RetryAfter, l.maxBackpressure()))
		}
		l.Record(failure, wait)
		if failure != nil && !failure.Outcome.Transient() {
			return failure
		}
	}
}

// Tick sends one heartbeat, retrying a transient failure once. A 429 is not
// retried in-tick; the next tick is delayed by Retry-After instead.
func (l *HeartbeatLoop) Tick(ctx context.Context) *HeartbeatFailure {
	l.seq++
	started := l.Now()
	failure := l.send(ctx)
	if failure != nil && failure.Outcome.RetryableInTick() {
		if !SleepContext(ctx, l.retryDelay()) {
			return nil
		}
		failure = l.send(ctx)
	}
	l.lastLatency = l.Now().Sub(started)
	l.lastAt = started
	return failure
}

func (l *HeartbeatLoop) send(ctx context.Context) *HeartbeatFailure {
	report := l.Report
	if l.PolicyBundle != nil {
		report.PolicyBundle = l.PolicyBundle()
	}
	if activations := l.pendingActivations(); len(activations) > 0 {
		report.ConnectorActivations = activations
	}
	if l.Versioned {
		report.Seq = l.seq
		report.Counters = &HeartbeatCounter{BeatsFailedSinceOK: l.failedSinceOK}
	}
	if err := l.Client.Heartbeat(ctx, l.Token, report); err != nil {
		return ClassifyHeartbeatError(err)
	}
	l.markActivationsReported(report.ConnectorActivations)
	return nil
}

// pendingActivations resolves the connector ids still owed a heartbeat
// activation report. A supplier error never blocks the beat: the ids are
// skipped this beat and picked up again on the next one.
func (l *HeartbeatLoop) pendingActivations() []ConnectorActivation {
	if l.ConnectorActivations == nil {
		return nil
	}
	ids, err := l.ConnectorActivations()
	if err != nil {
		if l.Warn != nil {
			fmt.Fprintf(l.Warn, "runtime heartbeat: skipping connector activation report: %v\n", err)
		}
		return nil
	}
	pending := make([]ConnectorActivation, 0, len(ids))
	for _, id := range ids {
		if id == "" || l.reportedActivations[id] {
			continue
		}
		pending = append(pending, ConnectorActivation{ConnectorID: id})
	}
	if len(pending) == 0 {
		return nil
	}
	return pending
}

// markActivationsReported records the ids carried by a beat the catalog
// accepted, so the loop stops re-reporting them in this process. A restart
// may re-report an id the catalog has already activated, which is a no-op
// there.
func (l *HeartbeatLoop) markActivationsReported(activations []ConnectorActivation) {
	if len(activations) == 0 {
		return
	}
	if l.reportedActivations == nil {
		l.reportedActivations = make(map[string]bool, len(activations))
	}
	for _, activation := range activations {
		l.reportedActivations[activation.ConnectorID] = true
	}
}

func (l *HeartbeatLoop) Record(failure *HeartbeatFailure, next time.Duration) {
	outcome, status := HeartbeatOK, 0
	if failure != nil {
		outcome, status = failure.Outcome, failure.StatusCode
		l.failedSinceOK++
	} else {
		l.failedSinceOK = 0
	}
	if l.Events != nil {
		seq, latency, nextMS := l.seq, l.lastLatency.Milliseconds(), next.Milliseconds()
		l.Events.Emit(HeartbeatEvent{
			Event:      "beat",
			Seq:        &seq,
			At:         l.lastAt.UTC().Format(time.RFC3339),
			Outcome:    outcome,
			HTTPStatus: status,
			LatencyMS:  &latency,
			NextInMS:   &nextMS,
		})
	} else if failure != nil && l.Warn != nil && failure.Outcome.Transient() {
		fmt.Fprintf(l.Warn, "runtime heartbeat: %s; retrying in %s\n", failure.Outcome, next.Round(time.Second))
	}
	l.emitLifecycleRecord(outcome)
}

func (l *HeartbeatLoop) emitLifecycleRecord(outcome HeartbeatOutcome) {
	if l.AppendLifecycle == nil {
		return
	}
	_ = l.AppendLifecycle(LifecycleEvent{
		EventClass:     EventClassLifecycle,
		SchemaVersion:  1,
		EventType:      "heartbeat",
		Outcome:        outcome,
		ObservedAt:     l.lastAt.UTC(),
		RuntimeVersion: l.Report.RuntimeVersion,
		RunID:          l.Report.RunID,
		Seq:            l.seq,
	})
}
