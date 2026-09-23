package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const heartbeatTestToken = "kh_live_runtime_test_token_1234567890"

// scriptedHeartbeatClient returns results in order and repeats the last one.
type scriptedHeartbeatClient struct {
	mu      sync.Mutex
	results []error
	reports []HeartbeatReport
}

func (c *scriptedHeartbeatClient) WhoAmI(context.Context, string) (*RuntimeIdentity, error) {
	return nil, errors.New("not used")
}

func (c *scriptedHeartbeatClient) Heartbeat(_ context.Context, _ string, report HeartbeatReport) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reports = append(c.reports, report)
	result := c.results[min(len(c.reports), len(c.results))-1]
	return result
}

func (c *scriptedHeartbeatClient) RegisterCredentialSyncKey(context.Context, string, string, string, string) error {
	return nil
}

func (c *scriptedHeartbeatClient) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.reports)
}

// syncBuffer lets a test read stdout while the loop is still writing it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func heartbeatEvents(t *testing.T, out string) []map[string]any {
	t.Helper()
	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("stdout line is not JSON: %q", line)
		}
		events = append(events, event)
	}
	return events
}

func eventsOf(events []map[string]any, kind string) []map[string]any {
	var matched []map[string]any
	for _, event := range events {
		if event["event"] == kind {
			matched = append(matched, event)
		}
	}
	return matched
}

func statusFailure(status int) error {
	return &HeartbeatFailure{Outcome: classifyHeartbeatStatus(status), StatusCode: status, Wrapped: fmt.Errorf("runtime heartbeat returned %d", status)}
}

func testLoop(client RuntimeClient, out io.Writer) *heartbeatLoop {
	return &heartbeatLoop{
		client:    client,
		token:     heartbeatTestToken,
		report:    HeartbeatReport{RuntimeVersion: "test", SchemaVersion: 2},
		versioned: true,
		interval:  20 * time.Millisecond,
		events:    &heartbeatEmitter{out: out, runID: "run-1"},
		now:       time.Now,
		jitter:    func(d time.Duration) time.Duration { return d },
	}
}

func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestHeartbeatLoopRetriesTransientFailureOnceWithinTick(t *testing.T) {
	client := &scriptedHeartbeatClient{results: []error{statusFailure(http.StatusServiceUnavailable), nil}}
	var out syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- testLoop(client, &out).run(ctx, true) }()
	waitFor(t, "the retried beat", func() bool { return len(eventsOf(heartbeatEvents(t, out.String()), "beat")) > 0 })
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("loop returned %v, want nil after cancellation", err)
	}
	beat := eventsOf(heartbeatEvents(t, out.String()), "beat")[0]
	if beat["outcome"] != "ok" || beat["seq"] != float64(1) {
		t.Fatalf("first beat = %v, want seq 1 recovered to ok by the in-tick retry", beat)
	}
	if client.reports[0].Seq != 1 || client.reports[1].Seq != 1 {
		t.Fatalf("the retry must reuse the tick's seq: %+v", client.reports[:2])
	}
}

// A catalog outage must not become a runtime crash: the loop keeps ticking and
// reports the outage as a catalog outcome, counting failures since the last ok.
func TestHeartbeatLoopKeepsRunningThroughCatalogOutage(t *testing.T) {
	client := &scriptedHeartbeatClient{results: []error{statusFailure(http.StatusBadGateway)}}
	var out syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- testLoop(client, &out).run(ctx, true) }()
	waitFor(t, "three failed ticks", func() bool { return len(eventsOf(heartbeatEvents(t, out.String()), "beat")) >= 3 })
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("loop exited with %v during a transient outage", err)
	}
	for _, beat := range eventsOf(heartbeatEvents(t, out.String()), "beat") {
		if beat["outcome"] != "catalog_error" || beat["http_status"] != float64(http.StatusBadGateway) {
			t.Fatalf("beat = %v, want catalog_error/502", beat)
		}
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	// Two attempts per tick; the third tick's reports carry two prior failures.
	if got := client.reports[4].Counters.BeatsFailedSinceOK; got != 2 {
		t.Fatalf("beats_failed_since_ok on third tick = %d, want 2", got)
	}
}

func TestHeartbeatLoopHonorsRetryAfterWithCap(t *testing.T) {
	for _, tc := range []struct {
		name       string
		retryAfter time.Duration
		wantNext   time.Duration
	}{
		{"within cap", 50 * time.Millisecond, 50 * time.Millisecond},
		{"capped at five intervals", time.Hour, 100 * time.Millisecond},
		{"never shorter than the interval", time.Millisecond, 20 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			throttled := &HeartbeatFailure{Outcome: HeartbeatCatalogBackpressure, StatusCode: http.StatusTooManyRequests, RetryAfter: tc.retryAfter, Wrapped: errors.New("throttled")}
			client := &scriptedHeartbeatClient{results: []error{throttled, nil}}
			var out syncBuffer
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- testLoop(client, &out).run(ctx, true) }()
			waitFor(t, "the throttled beat", func() bool { return len(eventsOf(heartbeatEvents(t, out.String()), "beat")) > 0 })
			cancel()
			<-done
			beat := eventsOf(heartbeatEvents(t, out.String()), "beat")[0]
			if beat["outcome"] != "catalog_backpressure" || beat["next_in_ms"] != float64(tc.wantNext.Milliseconds()) {
				t.Fatalf("beat = %v, want catalog_backpressure with next_in_ms %d", beat, tc.wantNext.Milliseconds())
			}
			if client.reports[0].Seq != 1 || (len(client.reports) > 1 && client.reports[1].Seq != 2) {
				t.Fatalf("a 429 must not be retried within the tick: %+v", client.reports)
			}
		})
	}
}

func TestHeartbeatLoopStopsOnTerminalCatalogResponses(t *testing.T) {
	for _, tc := range []struct {
		status  int
		outcome HeartbeatOutcome
	}{
		{http.StatusUnauthorized, HeartbeatUnauthorized},
		{http.StatusForbidden, HeartbeatUnauthorized},
		{http.StatusBadRequest, HeartbeatCatalogRejected},
	} {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			client := &scriptedHeartbeatClient{results: []error{statusFailure(tc.status)}}
			var out syncBuffer
			err := testLoop(client, &out).run(context.Background(), true)
			var failure *HeartbeatFailure
			if !errors.As(err, &failure) || failure.Outcome != tc.outcome {
				t.Fatalf("loop returned %v, want %s", err, tc.outcome)
			}
			if client.calls() != 1 {
				t.Fatalf("heartbeat calls = %d, want 1 (terminal responses are not retried)", client.calls())
			}
		})
	}
}

func TestHeartbeatLoopStopsPromptlyWhenCancelledDuringRetryDelay(t *testing.T) {
	client := &scriptedHeartbeatClient{results: []error{statusFailure(http.StatusServiceUnavailable)}}
	loop := testLoop(client, io.Discard)
	loop.interval = time.Minute // retry delay is min(5s, interval/4) = 5s
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- loop.run(ctx, true) }()
	waitFor(t, "the first attempt", func() bool { return client.calls() == 1 })
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("loop returned %v, want nil on cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("loop did not stop within 1s of cancellation")
	}
}

func TestRuntimeClientClassifiesHeartbeatResponses(t *testing.T) {
	for _, tc := range []struct {
		status     int
		retryAfter string
		outcome    HeartbeatOutcome
		wantAfter  time.Duration
	}{
		{http.StatusUnauthorized, "", HeartbeatUnauthorized, 0},
		{http.StatusForbidden, "", HeartbeatUnauthorized, 0},
		{http.StatusBadRequest, "", HeartbeatCatalogRejected, 0},
		{http.StatusTooManyRequests, "7", HeartbeatCatalogBackpressure, 7 * time.Second},
		{http.StatusTooManyRequests, "soon", HeartbeatCatalogBackpressure, 0},
		{http.StatusInternalServerError, "", HeartbeatCatalogError, 0},
		{http.StatusServiceUnavailable, "", HeartbeatCatalogError, 0},
	} {
		t.Run(fmt.Sprint(tc.status, tc.retryAfter), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.retryAfter != "" {
					w.Header().Set("Retry-After", tc.retryAfter)
				}
				w.WriteHeader(tc.status)
			}))
			defer server.Close()
			err := NewRuntimeClient(server.URL, time.Second).Heartbeat(context.Background(), heartbeatTestToken, HeartbeatReport{RuntimeVersion: "test"})
			var failure *HeartbeatFailure
			if !errors.As(err, &failure) || failure.Outcome != tc.outcome || failure.StatusCode != tc.status || failure.RetryAfter != tc.wantAfter {
				t.Fatalf("Heartbeat() = %#v, want %s/%d retry-after %s", failure, tc.outcome, tc.status, tc.wantAfter)
			}
			if strings.Contains(err.Error(), heartbeatTestToken) {
				t.Fatal("heartbeat error must not contain the token")
			}
		})
	}

	t.Run("timeout", func(t *testing.T) {
		release := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
		defer server.Close()
		defer close(release)
		err := NewRuntimeClient(server.URL, 20*time.Millisecond).Heartbeat(context.Background(), heartbeatTestToken, HeartbeatReport{RuntimeVersion: "test"})
		if got := classifyHeartbeatError(err).Outcome; got != HeartbeatCatalogTimeout {
			t.Fatalf("outcome = %s, want catalog_timeout", got)
		}
	})

	t.Run("unreachable", func(t *testing.T) {
		server := httptest.NewServer(http.NotFoundHandler())
		url := server.URL
		server.Close()
		err := NewRuntimeClient(url, time.Second).Heartbeat(context.Background(), heartbeatTestToken, HeartbeatReport{RuntimeVersion: "test"})
		if got := classifyHeartbeatError(err).Outcome; got != HeartbeatCatalogUnreachable {
			t.Fatalf("outcome = %s, want catalog_unreachable", got)
		}
	})
}

// fakeCatalog is a minimal policy-catalog double recording heartbeat bodies.
type fakeCatalog struct {
	mu              sync.Mutex
	whoami          func(w http.ResponseWriter)
	heartbeatStatus int
	hangHeartbeats  chan struct{} // when set, heartbeats block until closed
	bodies          []map[string]any
	rawBodies       []string
	whoamiCalls     int
}

func newFakeCatalog(t *testing.T) (*fakeCatalog, *httptest.Server) {
	catalog := &fakeCatalog{heartbeatStatus: http.StatusNoContent}
	workspace := "workspace-1"
	catalog.whoami = func(w http.ResponseWriter) {
		json.NewEncoder(w).Encode(RuntimeIdentity{ID: "installation-1", OrgID: "org-1", WorkspaceID: &workspace, Platform: "discord", Status: "active", BindingStatus: "verified"})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/runtime/whoami":
			catalog.mu.Lock()
			catalog.whoamiCalls++
			whoami := catalog.whoami
			catalog.mu.Unlock()
			whoami(w)
		case "/api/v1/runtime/heartbeat":
			raw, _ := io.ReadAll(r.Body)
			var body map[string]any
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Errorf("heartbeat body is not JSON: %q", raw)
			}
			catalog.mu.Lock()
			catalog.bodies = append(catalog.bodies, body)
			catalog.rawBodies = append(catalog.rawBodies, string(raw))
			status, hang := catalog.heartbeatStatus, catalog.hangHeartbeats
			catalog.mu.Unlock()
			if hang != nil {
				select {
				case <-hang:
				case <-r.Context().Done():
				}
				return
			}
			w.WriteHeader(status)
		default:
			t.Errorf("unexpected runtime path %q", r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	return catalog, server
}

func (c *fakeCatalog) whoamis() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.whoamiCalls
}

func (c *fakeCatalog) heartbeats() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.bodies)
}

func envMap(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

type heartbeatRun struct {
	stdout syncBuffer
	stderr syncBuffer
	code   chan int
	cancel context.CancelFunc
}

func startHeartbeat(t *testing.T, server *httptest.Server, stdin io.Reader, env map[string]string, args ...string) *heartbeatRun {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	run := &heartbeatRun{code: make(chan int, 1), cancel: cancel}
	t.Cleanup(cancel)
	cfg := Config{RuntimeToken: heartbeatTestToken, RuntimeControlPlaneURL: server.URL}
	go func() {
		run.code <- runRuntimeHeartbeat(ctx, append([]string{"--interval", "1s", "--timeout", "1s"}, args...), stdin, &run.stdout, &run.stderr, cfg, envMap(env), NewRuntimeClient)
	}()
	return run
}

func (r *heartbeatRun) exit(t *testing.T) int {
	t.Helper()
	select {
	case code := <-r.code:
		return code
	case <-time.After(3 * time.Second):
		t.Fatal("runtime heartbeat did not exit")
		return -1
	}
}

var supervisedEnv = map[string]string{
	"KEI_HARNESS_KIND":          "chat-discord",
	"KEI_HARNESS_VERSION":       "2026.09.23",
	"KEI_DEPLOYMENT_ENV":        "prod",
	"KEI_AGENTWARE_SDK_LANG":    "python",
	"KEI_AGENTWARE_SDK_VERSION": "0.4.0",
	"KEI_HEARTBEAT_RUN_ID":      "3f0c9f5e-6a55-4d2c-9d0e-2f7e0c1b9a10",
}

func TestRuntimeHeartbeatJSONLReportsIdentityAndV2Beat(t *testing.T) {
	catalog, server := newFakeCatalog(t)
	run := startHeartbeat(t, server, nil, supervisedEnv, "--output", "jsonl")
	waitFor(t, "the first beat event", func() bool { return len(eventsOf(heartbeatEvents(t, run.stdout.String()), "beat")) > 0 })
	run.cancel()
	if code := run.exit(t); code != heartbeatExitOK {
		t.Fatalf("exit = %d, want 0 on cancellation; stderr=%s", code, run.stderr.String())
	}

	events := heartbeatEvents(t, run.stdout.String())
	if events[0]["event"] != "identity" || events[0]["installation_id"] != "installation-1" || events[0]["workspace_id"] != "workspace-1" || events[0]["run_id"] != supervisedEnv["KEI_HEARTBEAT_RUN_ID"] || events[0]["v"] != float64(1) {
		t.Fatalf("first event = %v, want the whoami identity", events[0])
	}
	beat := eventsOf(events, "beat")[0]
	if beat["outcome"] != "ok" || beat["seq"] != float64(1) || beat["http_status"] != nil || beat["next_in_ms"] == nil {
		t.Fatalf("beat = %v", beat)
	}
	if catalog.whoamis() != 1 {
		t.Fatalf("whoami calls = %d, want 1", catalog.whoamis())
	}

	catalog.mu.Lock()
	body := catalog.bodies[0]
	catalog.mu.Unlock()
	wantKeys := []string{"counters", "harness", "interval_seconds", "run_id", "runtime_started_at", "runtime_version", "schema_version", "seq"}
	if len(body) != len(wantKeys) {
		t.Fatalf("v2 body keys = %v, want exactly %v", body, wantKeys)
	}
	for _, key := range wantKeys {
		if _, ok := body[key]; !ok {
			t.Fatalf("v2 body is missing %q: %v", key, body)
		}
	}
	harness := body["harness"].(map[string]any)
	if harness["kind"] != "chat-discord" || harness["sdk_lang"] != "python" || harness["link"] != nil {
		t.Fatalf("harness envelope = %v", harness)
	}
	if body["schema_version"] != float64(2) || body["interval_seconds"] != float64(1) || body["run_id"] != supervisedEnv["KEI_HEARTBEAT_RUN_ID"] {
		t.Fatalf("v2 body = %v", body)
	}
}

// Identity is authoritative only from the token. The heartbeat body carries no
// installation, org, or workspace field, even when the harness declares one.
func TestRuntimeHeartbeatNeverForwardsDeclaredIdentity(t *testing.T) {
	catalog, server := newFakeCatalog(t)
	env := map[string]string{"KEI_HARNESS_KIND": "assistant", "KEI_ORG_ID": "org-declared", "KEI_WORKSPACE_ID": "workspace-declared", "KEI_RUNTIME_INSTALLATION_ID": "installation-declared"}
	run := startHeartbeat(t, server, nil, env, "--output", "jsonl")
	waitFor(t, "a heartbeat", func() bool { return catalog.heartbeats() > 0 })
	run.cancel()
	run.exit(t)
	catalog.mu.Lock()
	raw := catalog.rawBodies[0]
	catalog.mu.Unlock()
	for _, leaked := range []string{"installation", "org_id", "workspace", "declared"} {
		if strings.Contains(raw, leaked) {
			t.Fatalf("heartbeat body contains %q: %s", leaked, raw)
		}
	}
	if identity := eventsOf(heartbeatEvents(t, run.stdout.String()), "identity")[0]; identity["org_id"] != "org-1" {
		t.Fatalf("identity event must come from whoami, got %v", identity)
	}
}

func TestRuntimeHeartbeatRedactsSecretsFromBodyAndOutput(t *testing.T) {
	const canary = "KEI_TEST_LEAK_CANARY_7f3a"
	catalog, server := newFakeCatalog(t)
	catalog.heartbeatStatus = http.StatusServiceUnavailable
	env := map[string]string{
		"KEI_HARNESS_KIND":            "assistant",
		"DISCORD_TOKEN":               canary,
		"TWILIO_AUTH_TOKEN":           canary,
		"KEI_CREDENTIAL_SYNC_PRIVATE": canary,
		"KEI_PROXY_INVOKING_SUBJECT":  canary,
	}
	run := startHeartbeat(t, server, nil, env, "--output", "jsonl")
	waitFor(t, "a failed beat event", func() bool { return len(eventsOf(heartbeatEvents(t, run.stdout.String()), "beat")) > 0 })
	run.cancel()
	run.exit(t)
	catalog.mu.Lock()
	bodies := strings.Join(catalog.rawBodies, "\n")
	catalog.mu.Unlock()
	for name, text := range map[string]string{"body": bodies, "stdout": run.stdout.String(), "stderr": run.stderr.String()} {
		if strings.Contains(text, canary) || strings.Contains(text, heartbeatTestToken) || strings.Contains(text, "Bearer") {
			t.Fatalf("%s leaks a secret: %s", name, text)
		}
	}
}

func TestRuntimeHeartbeatRejectsMalformedHarnessMetadata(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"KEI_HARNESS_KIND", "evil"},
		{"KEI_HARNESS_VERSION", "1.0 kh_live_misplaced_secret"},
		{"KEI_HARNESS_VERSION", strings.Repeat("9", 65)},
		{"KEI_DEPLOYMENT_ENV", "prod\n"},
		{"KEI_AGENTWARE_SDK_LANG", "rust"},
		{"KEI_AGENTWARE_SDK_VERSION", "0.4.0;rm"},
		{"KEI_HEARTBEAT_RUN_ID", "run id with spaces"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			catalog, server := newFakeCatalog(t)
			run := startHeartbeat(t, server, nil, map[string]string{tc.name: tc.value}, "--output", "jsonl")
			if code := run.exit(t); code != heartbeatExitConfig {
				t.Fatalf("exit = %d, want %d", code, heartbeatExitConfig)
			}
			events := heartbeatEvents(t, run.stdout.String())
			if len(events) != 1 || events[0]["event"] != "terminal" || events[0]["reason"] != "config_invalid" || events[0]["run_id"] == "" {
				t.Fatalf("events = %v, want one terminal config_invalid", events)
			}
			if catalog.whoamis() != 0 || catalog.heartbeats() != 0 {
				t.Fatal("invalid config must fail before contacting the catalog")
			}
			if !strings.Contains(run.stderr.String(), tc.name) || strings.Contains(run.stderr.String(), strings.TrimSpace(tc.value)) {
				t.Fatalf("stderr %q must name %s without echoing its value", run.stderr.String(), tc.name)
			}
		})
	}
}

func TestRuntimeHeartbeatRejectsMalformedIdentityResponse(t *testing.T) {
	catalog, server := newFakeCatalog(t)
	catalog.whoami = func(w http.ResponseWriter) { fmt.Fprint(w, `{"id":"installation-1"}`) }
	run := startHeartbeat(t, server, nil, nil, "--output", "jsonl")
	if code := run.exit(t); code != heartbeatExitContract {
		t.Fatalf("exit = %d, want %d", code, heartbeatExitContract)
	}
	if events := heartbeatEvents(t, run.stdout.String()); len(events) != 1 || events[0]["reason"] != "contract_mismatch" {
		t.Fatalf("events = %v, want terminal contract_mismatch", events)
	}
	if catalog.heartbeats() != 0 {
		t.Fatal("no heartbeat may be sent without a complete identity")
	}
}

func TestRuntimeHeartbeatUnauthorizedIsTerminal(t *testing.T) {
	t.Run("revoked at whoami", func(t *testing.T) {
		catalog, server := newFakeCatalog(t)
		catalog.whoami = func(w http.ResponseWriter) { w.WriteHeader(http.StatusUnauthorized) }
		run := startHeartbeat(t, server, nil, nil, "--output", "jsonl")
		if code := run.exit(t); code != heartbeatExitUnauthorized {
			t.Fatalf("exit = %d, want %d", code, heartbeatExitUnauthorized)
		}
		if events := heartbeatEvents(t, run.stdout.String()); len(events) != 1 || events[0]["event"] != "terminal" || events[0]["reason"] != "unauthorized" {
			t.Fatalf("events = %v", events)
		}
		if catalog.whoamis() != 1 || catalog.heartbeats() != 0 {
			t.Fatalf("whoami=%d heartbeats=%d, want one whoami and no retry", catalog.whoamis(), catalog.heartbeats())
		}
	})
	t.Run("revoked at heartbeat", func(t *testing.T) {
		catalog, server := newFakeCatalog(t)
		catalog.heartbeatStatus = http.StatusUnauthorized
		run := startHeartbeat(t, server, nil, nil, "--output", "jsonl")
		if code := run.exit(t); code != heartbeatExitUnauthorized {
			t.Fatalf("exit = %d, want %d", code, heartbeatExitUnauthorized)
		}
		events := heartbeatEvents(t, run.stdout.String())
		last := events[len(events)-1]
		if beat := eventsOf(events, "beat")[0]; beat["outcome"] != "unauthorized" || last["event"] != "terminal" || last["reason"] != "unauthorized" {
			t.Fatalf("events = %v", events)
		}
		if catalog.heartbeats() != 1 {
			t.Fatalf("heartbeats = %d, want 1 (unauthorized is not retried)", catalog.heartbeats())
		}
	})
}

// A catalog outage at startup is reported as a catalog outcome and retried,
// not surfaced as a crashing runtime.
func TestRuntimeHeartbeatRetriesTransientWhoamiFailure(t *testing.T) {
	catalog, server := newFakeCatalog(t)
	healthy := catalog.whoami
	catalog.whoami = func(w http.ResponseWriter) {
		catalog.mu.Lock()
		catalog.whoami = healthy
		catalog.mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	run := startHeartbeat(t, server, nil, nil, "--output", "jsonl")
	waitFor(t, "an ok beat", func() bool {
		for _, beat := range eventsOf(heartbeatEvents(t, run.stdout.String()), "beat") {
			if beat["outcome"] == "ok" {
				return true
			}
		}
		return false
	})
	run.cancel()
	run.exit(t)
	events := heartbeatEvents(t, run.stdout.String())
	if len(eventsOf(events, "terminal")) != 0 || len(eventsOf(events, "identity")) != 1 {
		t.Fatalf("events = %v, want recovery without a terminal event", events)
	}
	if catalog.whoamis() != 2 {
		t.Fatalf("whoami calls = %d, want 2 (one in-tick retry)", catalog.whoamis())
	}
}

// When the supervising harness dies, its end of the stdin pipe closes. The
// child must exit promptly, even mid-request, rather than keep reporting a dead
// harness as live.
func TestRuntimeHeartbeatExitsWhenParentStdinCloses(t *testing.T) {
	catalog, server := newFakeCatalog(t)
	catalog.hangHeartbeats = make(chan struct{})
	defer close(catalog.hangHeartbeats)
	stdin, parent := io.Pipe()
	run := startHeartbeat(t, server, stdin, supervisedEnv, "--output", "jsonl", "--parent-stdin", "--timeout", "30s")
	waitFor(t, "an in-flight heartbeat", func() bool { return catalog.heartbeats() > 0 })
	parent.Close()
	select {
	case code := <-run.code:
		if code != heartbeatExitOK {
			t.Fatalf("exit = %d, want 0 on parent exit", code)
		}
	case <-time.After(time.Second):
		t.Fatal("runtime heartbeat did not exit within 1s of stdin EOF")
	}
	catalog.mu.Lock()
	harness := catalog.bodies[0]["harness"].(map[string]any)
	catalog.mu.Unlock()
	if harness["link"] != "attached" {
		t.Fatalf("harness.link = %v, want attached under --parent-stdin", harness["link"])
	}
}

func TestRuntimeHeartbeatRejectsUnknownOutput(t *testing.T) {
	_, server := newFakeCatalog(t)
	run := startHeartbeat(t, server, nil, nil, "--output", "yaml")
	if code := run.exit(t); code != heartbeatExitContract {
		t.Fatalf("exit = %d, want %d", code, heartbeatExitContract)
	}
}

// Without --output, heartbeat keeps its legacy contract: the bootstrap identity
// line, a v1 body that is only runtime_version, no per-beat stdout, and the
// harness envelope ignored even when set.
func TestRuntimeHeartbeatLegacyTextModeIsUnchanged(t *testing.T) {
	catalog, server := newFakeCatalog(t)
	run := startHeartbeat(t, server, nil, supervisedEnv)
	waitFor(t, "the bootstrap heartbeat", func() bool { return catalog.heartbeats() > 0 })
	run.cancel()
	if code := run.exit(t); code != heartbeatExitOK {
		t.Fatalf("exit = %d, want 0; stderr=%s", code, run.stderr.String())
	}
	want := "{\"installation_id\":\"installation-1\",\"org_id\":\"org-1\",\"workspace_id\":\"workspace-1\",\"platform\":\"discord\",\"status\":\"active\",\"binding_status\":\"verified\"}\n"
	if run.stdout.String() != want {
		t.Fatalf("stdout = %q, want the legacy identity line %q", run.stdout.String(), want)
	}
	catalog.mu.Lock()
	raw := catalog.rawBodies[0]
	catalog.mu.Unlock()
	if raw != fmt.Sprintf("{\"runtime_version\":%q}", version) {
		t.Fatalf("legacy body = %s, want the v1 body", raw)
	}
}

func TestRuntimeHeartbeatLegacyExitsOneWhenRevoked(t *testing.T) {
	catalog, server := newFakeCatalog(t)
	run := startHeartbeat(t, server, nil, nil)
	waitFor(t, "the bootstrap heartbeat", func() bool { return catalog.heartbeats() > 0 })
	catalog.mu.Lock()
	catalog.heartbeatStatus = http.StatusUnauthorized
	catalog.mu.Unlock()
	if code := run.exit(t); code != heartbeatExitTransient {
		t.Fatalf("legacy exit = %d, want 1", code)
	}
	if !strings.Contains(run.stderr.String(), "401") || strings.Contains(run.stderr.String(), heartbeatTestToken) {
		t.Fatalf("stderr = %q", run.stderr.String())
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 9, 23, 17, 0, 0, 0, time.UTC)
	for value, want := range map[string]time.Duration{
		"":                              0,
		"10":                            10 * time.Second,
		"-3":                            0,
		"later":                         0,
		"Wed, 23 Sep 2026 17:00:30 GMT": 30 * time.Second,
		"Wed, 23 Sep 2026 16:59:00 GMT": 0,
	} {
		if got := parseRetryAfter(value, now); got != want {
			t.Errorf("parseRetryAfter(%q) = %s, want %s", value, got, want)
		}
	}
}

func TestJitterIntervalStaysWithinTenPercent(t *testing.T) {
	for range 1000 {
		if got := jitterInterval(time.Minute); got < 54*time.Second || got > 66*time.Second {
			t.Fatalf("jitterInterval(1m) = %s, outside ±10%%", got)
		}
	}
}
