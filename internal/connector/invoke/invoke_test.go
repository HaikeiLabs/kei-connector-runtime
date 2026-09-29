package invoke

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseConnectorInvokeArgsPropagatesContext(t *testing.T) {
	t.Setenv("KEI_RUNTIME_TOKEN", "kh_live_harness_token_1234567890")
	t.Setenv("KEI_PROXY_INVOKING_SUBJECT", "human-1")
	t.Setenv("KEI_PROXY_AGENT_ID", "agent-9")
	t.Setenv("KEI_PROXY_FRAMEWORK", "claude")

	plan, err := parseConnectorInvokeArgs([]string{
		"--connector", "conn-1",
		"--capability", "lead.read",
		"--action", "read",
		"--resource", "leads/42",
		"--trace-id", "trace-1",
		"--idempotency-key", "idem-1",
		"--approval-id", "approval-1",
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
	if req.TraceID != "trace-1" || req.IdempotencyKey != "idem-1" || req.ApprovalID != "approval-1" {
		t.Fatalf("trace/idempotency/approval = %+v", req)
	}
	if req.InvokingSubject != "human-1" || req.UserID != "u-1" || req.AgentID != "agent-9" || req.Framework != "claude" {
		t.Fatalf("propagation context = %+v", req)
	}
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
		"--abac-url", "http://override:9000",
	}, testEnv())
	if err != nil {
		t.Fatalf("runtime parse: %v", err)
	}
	if plan.req.HarnessToken != "kh_live_runtime_token_1234567890" {
		t.Fatalf("harness_token = %q, want the runtime token", plan.req.HarnessToken)
	}
	// Runtime mode always uses the control-plane URL, not an --abac-url override.
	if plan.abacURL != "https://control.example.test" {
		t.Fatalf("runtime abac_url = %q, want the control-plane URL", plan.abacURL)
	}
	if plan.abacSecret != "" {
		t.Fatalf("runtime must never receive ABAC_API_SECRET, got %q", plan.abacSecret)
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

	client := NewClient(server.URL, "proxy-secret", 5*time.Second)
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
	if gotKey != "proxy-secret" {
		t.Fatalf("X-KEI-API-Key = %q, want proxy-secret", gotKey)
	}
}

// TestInvokeConnectorSurfacesStructuredDeny: a 200 deny from the engine (e.g.
// "approval required" from an approval_required policy) must surface with its
// reason so the harness can report why the call was refused.
func TestInvokeConnectorSurfacesStructuredDeny(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":"deny","reason":"approval required"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "proxy-secret", 5*time.Second)
	resp, err := client.Invoke(context.Background(), Request{
		ConnectorID: "conn-1",
		Capability:  "lead.read",
		Action:      "read",
		Resource:    "leads/42",
		TraceID:     "trace-1",
	})
	if err != nil {
		t.Fatalf("InvokeConnector: %v", err)
	}
	if resp.Decision != "deny" {
		t.Fatalf("decision = %q, want deny", resp.Decision)
	}
	if resp.Reason != "approval required" {
		t.Fatalf("reason = %q, want approval required", resp.Reason)
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

			client := NewClient(server.URL, "wrong-secret", 5*time.Second)
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

	client := NewClient(server.URL, "secret", 5*time.Second)
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
		ABACURL:                envOr("ABAC_URL", "http://localhost:8080"),
		ABACSecret:             strings.TrimSpace(os.Getenv("ABAC_API_SECRET")),
	}
}
