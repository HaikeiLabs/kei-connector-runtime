package connectorruntime

import (
	"context"
	"encoding/json"
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
			if heartbeat["runtime_version"] != version {
				t.Fatalf("runtime_version = %q, want the build-time version %q", heartbeat["runtime_version"], version)
			}
			requests++
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected runtime path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	identity, err := bootstrapRuntime(context.Background(), Config{RuntimeToken: "kh_live_runtime_test_token_1234567890", RuntimeControlPlaneURL: server.URL}, time.Second)
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
