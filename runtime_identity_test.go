package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBootstrapRuntimeResolvesInstallationAndReportsHeartbeat(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer kh_live_runtime_test_token_1234567890" {
			t.Fatalf("Authorization = %q", got)
		}
		switch r.URL.Path {
		case "/api/v1/runtime/whoami":
			if r.Method != http.MethodGet {
				t.Fatalf("whoami method = %s", r.Method)
			}
			requests++
			json.NewEncoder(w).Encode(RuntimeIdentity{ID: "installation-1", OrgID: "org-1", AgentID: "agent-1", Platform: "teams", Status: "pending", BindingStatus: "unverified"})
		case "/api/v1/runtime/heartbeat":
			if r.Method != http.MethodPost {
				t.Fatalf("heartbeat method = %s", r.Method)
			}
			var heartbeat map[string]string
			if err := json.NewDecoder(r.Body).Decode(&heartbeat); err != nil {
				t.Fatal(err)
			}
			if heartbeat["runtime_version"] != "2026.08.26" {
				t.Fatalf("runtime_version = %q", heartbeat["runtime_version"])
			}
			requests++
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected runtime path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	identity, err := bootstrapRuntime(context.Background(), Config{RuntimeToken: "kh_live_runtime_test_token_1234567890", RuntimeControlPlaneURL: server.URL, RuntimeVersion: "2026.08.26"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if identity.OrgID != "org-1" || identity.AgentID != "agent-1" || identity.Platform != "teams" {
		t.Fatalf("unexpected runtime identity: %#v", identity)
	}
	if requests != 2 {
		t.Fatalf("runtime requests = %d, want 2", requests)
	}
}

func TestWhoAmIRoundTripsWorkspaceID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/runtime/whoami" {
			t.Fatalf("unexpected runtime path %q", r.URL.Path)
		}
		fmt.Fprint(w, `{"id":"installation-1","org_id":"org-1","workspace_id":"workspace-9","platform":"discord","status":"active","binding_status":"verified"}`)
	}))
	defer server.Close()

	identity, err := NewRuntimeClient(server.URL, time.Second).WhoAmI(context.Background(), "runtime-token")
	if err != nil {
		t.Fatal(err)
	}
	if identity.WorkspaceID == nil {
		t.Fatal("workspace_id = nil, want \"workspace-9\"")
	}
	if *identity.WorkspaceID != "workspace-9" {
		t.Fatalf("workspace_id = %q, want \"workspace-9\"", *identity.WorkspaceID)
	}
}

func TestWhoAmIOmittedWorkspaceIDStaysNil(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id":"installation-1","org_id":"org-1","platform":"discord","status":"active","binding_status":"verified"}`)
	}))
	defer server.Close()

	identity, err := NewRuntimeClient(server.URL, time.Second).WhoAmI(context.Background(), "runtime-token")
	if err != nil {
		t.Fatal(err)
	}
	if identity.WorkspaceID != nil {
		t.Fatalf("workspace_id = %q, want nil", *identity.WorkspaceID)
	}
}

func TestRuntimeClientFailsClosedOnRejectedRuntimeToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	if _, err := NewRuntimeClient(server.URL, time.Second).WhoAmI(context.Background(), "bad-token"); err == nil {
		t.Fatal("expected rejected runtime token to fail")
	}
}
