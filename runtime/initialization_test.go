package runtime

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// initServer spins up a fake ABAC engine that records the last request and
// responds from the supplied handler.
func initServer(t *testing.T, handler http.HandlerFunc) (string, *http.Request) {
	t.Helper()
	var last *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		last = r
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, last
}

func TestInitializeMemberSuccess(t *testing.T) {
	var gotPath, gotMethod, gotKey string
	var gotBody MemberInitRequest
	url, _ := initServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		gotKey = r.Header.Get("X-KEI-API-Key")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"user_id":"u1","org_id":"o1","role":"member","group_id":"g1","initialized":true}`))
	})

	client := NewInitializationClient(url, "svc-secret", 5*time.Second)
	out, err := client.InitializeMember(context.Background(), MemberInitRequest{UserID: "u1", OrgID: "o1"})
	if err != nil {
		t.Fatalf("InitializeMember: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/v1/initialize" {
		t.Errorf("request = %s %s, want POST /api/v1/initialize", gotMethod, gotPath)
	}
	if gotKey != "svc-secret" {
		t.Errorf("X-KEI-API-Key = %q, want svc-secret", gotKey)
	}
	if gotBody.UserID != "u1" || gotBody.OrgID != "o1" {
		t.Errorf("body = %+v, want user u1 / org o1", gotBody)
	}
	if !out.Initialized || out.Role != "member" || out.GroupID != "g1" {
		t.Errorf("unexpected response: %+v", out)
	}
}

// TestInitializeMemberFailClosed pins the no-local-fallback contract: a
// non-200 from ABAC is surfaced as an error, never a synthesized success.
func TestInitializeMemberFailClosed(t *testing.T) {
	url, _ := initServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "member initialization failed; retry: org not found", http.StatusInternalServerError)
	})
	client := NewInitializationClient(url, "", 5*time.Second)
	out, err := client.InitializeMember(context.Background(), MemberInitRequest{UserID: "u1", OrgID: "missing"})
	if err == nil {
		t.Fatal("expected error on 500 (fail closed), got nil")
	}
	if out != nil {
		t.Errorf("expected nil response on failure, got %+v", out)
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should carry the status, got: %v", err)
	}
}

// TestInitializeMemberTransportError pins fail-closed behavior when the ABAC
// engine is unreachable.
func TestInitializeMemberTransportError(t *testing.T) {
	client := NewInitializationClient("http://127.0.0.1:0", "", 5*time.Second)
	if _, err := client.InitializeMember(context.Background(), MemberInitRequest{UserID: "u1", OrgID: "o1"}); err == nil {
		t.Fatal("expected transport error, got nil")
	}
}

func TestInitializeAgentSuccess(t *testing.T) {
	var gotPath, gotOrg, gotKey string
	var gotBody AgentInitRequest
	url, _ := initServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotOrg = r.URL.Query().Get("org_id")
		gotKey = r.Header.Get("X-KEI-API-Key")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"a1","status":"ready","initialized":true}`))
	})

	client := NewInitializationClient(url, "svc-secret", 5*time.Second)
	out, err := client.InitializeAgent(context.Background(), AgentInitRequest{
		OrgID:              "o1",
		Name:               "researcher",
		DeclaredTools:      json.RawMessage(`["search_wiki","search_web"]`),
		DeclaredDataScopes: json.RawMessage(`["wiki:read"]`),
	})
	if err != nil {
		t.Fatalf("InitializeAgent: %v", err)
	}
	if gotPath != "/api/v1/agents" {
		t.Errorf("path = %q, want /api/v1/agents", gotPath)
	}
	if gotOrg != "o1" {
		t.Errorf("org_id query = %q, want o1", gotOrg)
	}
	if gotKey != "svc-secret" {
		t.Errorf("X-KEI-API-Key = %q, want svc-secret", gotKey)
	}
	if gotBody.Name != "researcher" {
		t.Errorf("body name = %q, want researcher", gotBody.Name)
	}
	if string(gotBody.DeclaredTools) != `["search_wiki","search_web"]` {
		t.Errorf("declared_tools = %s", string(gotBody.DeclaredTools))
	}
	if !out.Initialized || out.Status != "ready" || out.ID != "a1" {
		t.Errorf("unexpected response: %+v", out)
	}
}

// TestInitializeAgentFailClosed pins the no-local-fallback contract for agent
// provisioning: an ABAC 500 is surfaced, never a synthesized agent.
func TestInitializeAgentFailClosed(t *testing.T) {
	url, _ := initServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "agent initialization failed; retry the request: org has no default workspace", http.StatusInternalServerError)
	})
	client := NewInitializationClient(url, "", 5*time.Second)
	out, err := client.InitializeAgent(context.Background(), AgentInitRequest{OrgID: "o1", Name: "a"})
	if err == nil {
		t.Fatal("expected error on 500 (fail closed), got nil")
	}
	if out != nil {
		t.Errorf("expected nil response on failure, got %+v", out)
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should carry the status, got: %v", err)
	}
}
