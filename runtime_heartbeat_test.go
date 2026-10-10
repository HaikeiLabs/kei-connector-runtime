package connectorruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

const heartbeatTestToken = "kh_live_runtime_test_token_1234567890"

// scriptedHeartbeatClient returns results in order and repeats the last one.
type scriptedHeartbeatClient struct {
	mu      sync.Mutex
	results []error
	reports []HeartbeatReport
}

func (c *scriptedHeartbeatClient) WhoAmI(_ context.Context, _ string) (*RuntimeIdentity, error) {
	return &RuntimeIdentity{ID: "installation-1", OrgID: "org-1", WorkspaceID: strPtr("workspace-1"), AgentID: "agent-1", Platform: "discord", Status: "active", BindingStatus: "verified"}, nil
}

func (c *scriptedHeartbeatClient) Heartbeat(_ context.Context, _ string, report HeartbeatReport) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reports = append(c.reports, report)
	result := c.results[min(len(c.reports), len(c.results))-1]
	return result
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

func TestRuntimeClientClassifiesHeartbeatResponses(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		want   HeartbeatOutcome
		status int
	}{
		{"ok", nil, HeartbeatOK, 0},
		{"non-204 status", &keiruntime.HeartbeatFailure{Outcome: keiruntime.HeartbeatCatalogError, StatusCode: http.StatusOK, Wrapped: errors.New("200")}, HeartbeatCatalogError, http.StatusOK},
		{"transport timeout", &keiruntime.HeartbeatFailure{Outcome: keiruntime.HeartbeatCatalogTimeout, Wrapped: context.DeadlineExceeded}, HeartbeatCatalogTimeout, 0},
		{"retryable status", &keiruntime.HeartbeatFailure{Outcome: keiruntime.HeartbeatCatalogError, StatusCode: http.StatusBadGateway, Wrapped: errors.New("502")}, HeartbeatCatalogError, http.StatusBadGateway},
		{"terminal status", &keiruntime.HeartbeatFailure{Outcome: keiruntime.HeartbeatCatalogRejected, StatusCode: http.StatusBadRequest, Wrapped: errors.New("400")}, HeartbeatCatalogRejected, http.StatusBadRequest},
		{"unauthorized", &keiruntime.HeartbeatFailure{Outcome: keiruntime.HeartbeatUnauthorized, StatusCode: http.StatusUnauthorized, Wrapped: errors.New("401")}, HeartbeatUnauthorized, http.StatusUnauthorized},
		{"backpressure", &keiruntime.HeartbeatFailure{Outcome: keiruntime.HeartbeatCatalogBackpressure, StatusCode: http.StatusTooManyRequests, Wrapped: errors.New("429")}, HeartbeatCatalogBackpressure, http.StatusTooManyRequests},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.want == HeartbeatOK {
				if tc.err != nil {
					t.Fatalf("Heartbeat() = %v, want nil", tc.err)
				}
				return
			}
			f := keiruntime.ClassifyHeartbeatError(tc.err)
			if f == nil {
				t.Fatalf("ClassifyHeartbeatError(%v) = nil, want failure", tc.err)
			}
			if f.Outcome != tc.want {
				t.Errorf("Outcome = %s, want %s", f.Outcome, tc.want)
			}
			if f.StatusCode != tc.status {
				t.Errorf("StatusCode = %d, want %d", f.StatusCode, tc.status)
			}
		})
	}
}

// fakeCatalog is a simple HTTP server that responds to /whoami and /heartbeat.
type fakeCatalog struct {
	mu              sync.Mutex
	whoami          func(http.ResponseWriter)
	heartbeatStatus int
	rawBodies       []string
	bodies          []map[string]any
	hangHeartbeats  chan struct{}
	whoamiCalls     int
}

func newFakeCatalog(t *testing.T) (*fakeCatalog, *httptest.Server) {
	t.Helper()
	c := &fakeCatalog{
		whoami: func(w http.ResponseWriter) {
			json.NewEncoder(w).Encode(RuntimeIdentity{ID: "installation-1", OrgID: "org-1", WorkspaceID: strPtr("workspace-1"), AgentID: "agent-1", Platform: "discord", Status: "active", BindingStatus: "verified"})
		},
		heartbeatStatus: http.StatusNoContent,
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/whoami"):
			c.mu.Lock()
			c.whoamiCalls++
			whoami := c.whoami
			c.mu.Unlock()
			whoami(w)

		case strings.HasSuffix(r.URL.Path, ":heartbeat"):
			c.mu.Lock()
			body, _ := io.ReadAll(r.Body)
			r.Body.Close()
			raw := string(body)
			c.rawBodies = append(c.rawBodies, raw)
			var parsed map[string]any
			json.Unmarshal(body, &parsed)
			c.bodies = append(c.bodies, parsed)
			status, hang := c.heartbeatStatus, c.hangHeartbeats
			c.mu.Unlock()

			if hang != nil {
				select {
				case <-hang:
				case <-r.Context().Done():
				}
			}
			w.WriteHeader(status)

		default:
			t.Errorf("unexpected runtime path %q", r.URL.Path)
		}
	}))
	t.Cleanup(s.Close)
	return c, s
}

func (c *fakeCatalog) heartbeats() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.bodies)
}

func (c *fakeCatalog) whoamis() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.whoamiCalls
}

var supervisedEnv = map[string]string{
	"KEI_HEARTBEAT_RUN_ID":      "test-run-id",
	"KEI_HARNESS_KIND":          "assistant",
	"KEI_HARNESS_VERSION":       "1.0",
	"KEI_AGENTWARE_SDK_LANG":    "python",
	"KEI_AGENTWARE_SDK_VERSION": "0.1.0",
	"KEI_DEPLOYMENT_ENV":        "test",
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

type heartbeatRun struct {
	code   chan int
	stdout syncBuffer
	stderr syncBuffer
	cancel func()
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

func envMap(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
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
	if len(events) < 2 {
		t.Fatalf("got %d events, want at least 2 (identity + beat)", len(events))
	}
	if identity := events[0]; identity["event"] != "identity" || identity["run_id"] != "test-run-id" || identity["org_id"] != "org-1" {
		t.Fatalf("first event = %v, want identity with run_id and org_id", identity)
	}
	if body := events[1]; body["event"] != "beat" || body["outcome"] != "ok" {
		t.Fatalf("second event = %v, want beat ok", body)
	}
	catalog.mu.Lock()
	body := catalog.bodies[0]
	catalog.mu.Unlock()
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
	// Wait for the identity line, not just the bootstrap POST: cancelling while
	// that POST's response is in flight is a graceful exit with no output.
	waitFor(t, "the identity line", func() bool { return strings.HasSuffix(run.stdout.String(), "\n") })
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

func TestRuntimeHeartbeatIdentityCarriesAssignedAgents(t *testing.T) {
	catalog, server := newFakeCatalog(t)
	catalog.whoami = func(w http.ResponseWriter) {
		json.NewEncoder(w).Encode(RuntimeIdentity{ID: "installation-1", OrgID: "org-1", AgentID: "agent-default", Platform: "cli", Status: "active", BindingStatus: "verified", Agents: []RuntimeAgent{
			{InstallationID: "installation-1", AgentID: "agent-default", IsDefault: true},
			{InstallationID: "installation-1", AgentID: "agent-2"},
		}})
	}
	run := startHeartbeat(t, server, nil, supervisedEnv, "--output", "jsonl")
	waitFor(t, "the first beat event", func() bool { return len(eventsOf(heartbeatEvents(t, run.stdout.String()), "beat")) > 0 })
	run.cancel()
	run.exit(t)

	identity := eventsOf(heartbeatEvents(t, run.stdout.String()), "identity")[0]
	if identity["agent_id"] != "agent-default" {
		t.Fatalf("agent_id = %v, want the whoami default", identity["agent_id"])
	}
	want := []any{
		map[string]any{"agent_id": "agent-default", "is_default": true},
		map[string]any{"agent_id": "agent-2", "is_default": false},
	}
	if !reflect.DeepEqual(identity["agents"], want) {
		t.Fatalf("agents = %v, want %v", identity["agents"], want)
	}
	if _, ok := identity["agents_truncated"]; ok {
		t.Fatalf("agents_truncated must be omitted for a list that fits: %v", identity)
	}
}
