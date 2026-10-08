package invoke

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseConnectorInvokeArgsRejectsInvokingSubjectFlag(t *testing.T) {
	t.Setenv("KEI_RUNTIME_TOKEN", "kh_live_runtime_token_1234567890")
	_, err := parseConnectorInvokeArgs([]string{
		"--connector", "conn-1",
		"--capability", "lead.read",
		"--action", "read",
		"--resource", "leads/42",
		"--invoking-subject", "victim",
	}, testEnv())
	if err == nil {
		t.Fatal("--invoking-subject must be rejected as an unknown flag")
	}
}

func TestParseConnectorInvokeArgsPropagatesContext(t *testing.T) {
	t.Setenv("KEI_RUNTIME_TOKEN", "kh_live_harness_token_1234567890")
	t.Setenv("KEI_PROXY_AGENT_ID", "agent-9")
	t.Setenv("KEI_PROXY_FRAMEWORK", "claude")

	plan, err := parseConnectorInvokeArgs([]string{
		"--connector", "conn-1",
		"--capability", "lead.read",
		"--action", "read",
		"--resource", "leads/42",
		"--trace-id", "trace-1",
		"--idempotency-key", "idem-1",
		"--user-id", "u-1",
	}, testEnv())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if plan.timeout != 30*time.Second {
		t.Fatalf("timeout = %v, want default 30s", plan.timeout)
	}
	req := plan.req
	if req.HarnessToken != "kh_live_harness_token_1234567890" {
		t.Fatalf("harness_token = %q", req.HarnessToken)
	}
	if req.ConnectorID != "conn-1" || req.Capability != "lead.read" || req.Action != "read" || req.Resource != "leads/42" {
		t.Fatalf("capability context = %+v", req)
	}
	if req.TraceID != "trace-1" || req.IdempotencyKey != "idem-1" {
		t.Fatalf("trace/idempotency = %+v", req)
	}
	if req.UserID != "u-1" || req.AgentID != "agent-9" || req.Framework != "claude" {
		t.Fatalf("propagation context = %+v", req)
	}
	// InvokingSubject is resolved from the session at Run time, not at parse time.
}

func TestParseConnectorInvokeArgsMintsTraceAndRequiresFields(t *testing.T) {
	t.Setenv("KEI_RUNTIME_TOKEN", "kh_live_harness_token_1234567890")

	plan, err := parseConnectorInvokeArgs([]string{
		"--connector", "conn-1",
		"--capability", "lead.read",
		"--action", "read",
		"--resource", "leads/42",
	}, testEnv())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	req := plan.req
	if req.TraceID == "" {
		t.Fatal("expected a minted trace id when none is supplied")
	}

	if _, err := parseConnectorInvokeArgs([]string{"--capability", "lead.read", "--action", "read", "--resource", "leads/42"}, testEnv()); err == nil {
		t.Fatal("missing --connector must fail")
	}
	if _, err := parseConnectorInvokeArgs([]string{"--connector", "conn-1", "--capability", "lead.read", "--action", "read"}, testEnv()); err == nil {
		t.Fatal("missing --resource must fail")
	}
}

func TestParseConnectorInvokeArgsRequiresToken(t *testing.T) {
	// No token set at all — must fail closed.
	if _, err := parseConnectorInvokeArgs([]string{
		"--connector", "conn-1",
		"--capability", "lead.read",
		"--action", "read",
		"--resource", "leads/42",
	}, testEnv()); err == nil {
		t.Fatal("missing runtime token must fail")
	}
}

func TestParseConnectorInvokeArgsRejectsKeyAlias(t *testing.T) {
	t.Setenv("KEI_RUNTIME_TOKEN", "kh_live_runtime_token_1234567890")
	_, err := parseConnectorInvokeArgs([]string{
		"--connector", "conn-1",
		"--capability", "lead.read",
		"--action", "read",
		"--resource", "leads/42",
		"--key", "kh_live_alias_token_1234567890",
	}, testEnv())
	if err == nil {
		t.Fatal("--key alias must be rejected")
	}
}

func TestParseConnectorInvokeArgsRuntimeRelayUsesControlPlaneURL(t *testing.T) {
	t.Setenv("KEI_RUNTIME_TOKEN", "kh_live_runtime_token_1234567890")
	t.Setenv("KEI_RUNTIME_CONTROL_PLANE_URL", "https://control.example.test")

	plan, err := parseConnectorInvokeArgs([]string{
		"--connector", "conn-1",
		"--capability", "lead.read",
		"--action", "read",
		"--resource", "leads/42",
	}, testEnv())
	if err != nil {
		t.Fatalf("runtime parse: %v", err)
	}
	if plan.req.HarnessToken != "kh_live_runtime_token_1234567890" {
		t.Fatalf("harness_token = %q, want the runtime token", plan.req.HarnessToken)
	}
	if plan.controlPlaneURL != "https://control.example.test" {
		t.Fatalf("control-plane URL = %q, want KEI_RUNTIME_CONTROL_PLANE_URL", plan.controlPlaneURL)
	}
}

// TestParseConnectorInvokeArgsRejectsRemovedABACURLFlag: the in-cluster
// ABAC_URL mode is gone, so --abac-url is an unknown flag, not a silent no-op.
func TestParseConnectorInvokeArgsRejectsRemovedABACURLFlag(t *testing.T) {
	t.Setenv("KEI_RUNTIME_TOKEN", "kh_live_runtime_token_1234567890")
	t.Setenv("KEI_RUNTIME_CONTROL_PLANE_URL", "https://control.example.test")

	_, err := parseConnectorInvokeArgs([]string{
		"--connector", "conn-1",
		"--capability", "lead.read",
		"--action", "read",
		"--resource", "leads/42",
		"--abac-url", "http://override:9000",
	}, testEnv())
	if err == nil {
		t.Fatal("--abac-url must be rejected")
	}
}

func TestInvokeConnectorPropagatesRequestAndCredential(t *testing.T) {
	var gotKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/data-connectors/invoke" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		gotKey = r.Header.Get("X-KEI-API-Key")
		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.HarnessToken != "kh_live_harness_token_1234567890" {
			t.Fatalf("harness_token = %q", req.HarnessToken)
		}
		if req.ConnectorID != "conn-1" || req.Capability != "lead.read" || req.Resource != "leads/42" || req.TraceID != "trace-1" || req.IdempotencyKey != "idem-1" {
			t.Fatalf("invocation = %+v", req)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":"allow"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	resp, err := client.Invoke(context.Background(), Request{
		HarnessToken:   "kh_live_harness_token_1234567890",
		ConnectorID:    "conn-1",
		Capability:     "lead.read",
		Action:         "read",
		Resource:       "leads/42",
		TraceID:        "trace-1",
		IdempotencyKey: "idem-1",
	})
	if err != nil {
		t.Fatalf("InvokeConnector: %v", err)
	}
	if resp.Decision != "allow" {
		t.Fatalf("decision = %q", resp.Decision)
	}
	if gotKey != "" {
		t.Fatalf("X-KEI-API-Key = %q, want none: the runtime token authenticates the request", gotKey)
	}
}

// TestInvokeConnectorFailsClosedOnRejectedCredentials: a 401/403 must surface
// as an error, never as a decision the harness could act on.
func TestInvokeConnectorFailsClosedOnRejectedCredentials(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"decision":"allow"}`))
			}))
			defer server.Close()

			client := NewClient(server.URL, 5*time.Second)
			resp, err := client.Invoke(context.Background(), Request{ConnectorID: "conn-1"})
			if err == nil {
				t.Fatalf("expected error on %d, got %+v", status, resp)
			}
			if resp != nil {
				t.Fatalf("expected nil response on %d, got %+v", status, resp)
			}
			if !strings.Contains(err.Error(), "rejected proxy credentials") {
				t.Errorf("error = %v, want it to name rejected credentials", err)
			}
		})
	}
}

// TestInvokeConnectorFailsClosedOnServerError: an engine 500 is an error, never
// an implicit deny that a caller could confuse with a policy decision.
func TestInvokeConnectorFailsClosedOnServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	resp, err := client.Invoke(context.Background(), Request{ConnectorID: "conn-1"})
	if err == nil {
		t.Fatalf("expected error on 500, got %+v", resp)
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("error = %v, want it to name the status", err)
	}
}

// testEnv mirrors how the root package builds Env from its Config, so these
// tests keep driving configuration through the environment.
func testEnv() Env {
	return Env{
		RuntimeToken:           os.Getenv("KEI_RUNTIME_TOKEN"),
		RuntimeControlPlaneURL: os.Getenv("KEI_RUNTIME_CONTROL_PLANE_URL"),
	}
}

func TestParseArgsTakesInputAndProviderUser(t *testing.T) {
	env := Env{RuntimeToken: "kh_live_runtime_token_1234567890", RuntimeControlPlaneURL: "https://control.example.test", ProviderUserID: "+15550000000"}
	base := []string{"--connector", "conn-1", "--capability", "message.search", "--action", "read", "--resource", "gmail/messages"}
	plan, err := parseConnectorInvokeArgs(append(base, "--input", `{"query":"x"}`, "--provider-user", "+15551234567"), env)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if plan.input != `{"query":"x"}` || plan.req.ProviderUserID != "+15551234567" {
		t.Fatalf("input = %q, provider_user_id = %q", plan.input, plan.req.ProviderUserID)
	}
	plan, err = parseConnectorInvokeArgs(base, env)
	if err != nil || plan.req.ProviderUserID != "+15550000000" {
		t.Fatalf("provider user default = %q, %v", plan.req.ProviderUserID, err)
	}
}

// The catalog gets the input's digest, never the input, plus the chat identity
// it resolves to the invoking Kei user.
func TestRunSendsTheInputDigestNotTheInput(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"decision":"deny","reason":"no matching policy"}`))
	}))
	defer server.Close()
	env := Env{RuntimeToken: "kh_live_runtime_token_1234567890", RuntimeControlPlaneURL: server.URL, Stdin: strings.NewReader(`{"query":"from:alice"}`)}
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--connector", "conn-1", "--capability", "message.search", "--action", "read", "--resource", "gmail/messages", "--provider-user", "+15551234567", "--input", "-"}, env, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 for a deny", code)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "from:alice") {
		t.Fatalf("catalog request carried the input: %s", raw)
	}
	digest, _ := got["input_digest"].(string)
	if !strings.HasPrefix(digest, "sha256:") || got["provider_user_id"] != "+15551234567" {
		t.Fatalf("request = %s", raw)
	}
}

func TestRunRejectsInvalidInputBeforeTheCatalog(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer server.Close()
	env := Env{RuntimeToken: "kh_live_runtime_token_1234567890", RuntimeControlPlaneURL: server.URL}
	for _, in := range []string{`["a"]`, `{"q":`, `{"q":"` + strings.Repeat("a", 17<<10) + `"}`} {
		var stdout, stderr bytes.Buffer
		if code := Run([]string{"--connector", "conn-1", "--capability", "message.search", "--action", "read", "--resource", "gmail/messages", "--input", in}, env, &stdout, &stderr); code != 1 {
			t.Fatalf("exit = %d for invalid input", code)
		}
		if strings.Contains(stderr.String(), "aaaa") {
			t.Fatal("error echoed the input")
		}
	}
	if calls != 0 {
		t.Fatalf("catalog called %d times with invalid input", calls)
	}
}

type fixedSubjectSource struct {
	subject string
	err     error
}

func (s *fixedSubjectSource) Subject(context.Context) (string, error) {
	return s.subject, s.err
}

func TestRunIgnoresInvokingSubjectEnvVar(t *testing.T) {
	t.Setenv("KEI_PROXY_INVOKING_SUBJECT", "victim")

	var got Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"decision":"deny","reason":"no matching policy"}`))
	}))
	defer server.Close()

	env := Env{
		RuntimeToken:           "kh_live_runtime_token_1234567890",
		RuntimeControlPlaneURL: server.URL,
		SubjectSource:          &fixedSubjectSource{subject: "session-user"},
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"--connector", "conn-1",
		"--capability", "lead.read",
		"--action", "read",
		"--resource", "leads/42",
	}, env, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (deny)", code)
	}
	if got.InvokingSubject != "session-user" {
		t.Fatalf("InvokingSubject = %q, want session-user (not victim)", got.InvokingSubject)
	}
}

func TestRunWithoutSubjectSourceLeavesInvokingSubjectEmpty(t *testing.T) {
	t.Setenv("KEI_PROXY_INVOKING_SUBJECT", "victim")

	var got Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"decision":"deny","reason":"no matching policy"}`))
	}))
	defer server.Close()

	env := Env{
		RuntimeToken:           "kh_live_runtime_token_1234567890",
		RuntimeControlPlaneURL: server.URL,
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"--connector", "conn-1",
		"--capability", "lead.read",
		"--action", "read",
		"--resource", "leads/42",
	}, env, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (deny)", code)
	}
	if got.InvokingSubject != "" {
		t.Fatalf("InvokingSubject = %q, want empty (no session, victim ignored)", got.InvokingSubject)
	}
}
