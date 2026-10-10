package connectorruntime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRuntimeIdentityDefaultAgentID(t *testing.T) {
	for _, tc := range []struct {
		name     string
		identity RuntimeIdentity
		want     string
	}{
		{name: "legacy top-level default", identity: RuntimeIdentity{ID: "installation-1", AgentID: "agent-legacy", Agents: []RuntimeAgent{{InstallationID: "installation-1", AgentID: "agent-other", IsDefault: true}}}, want: "agent-legacy"},
		{name: "assigned default", identity: RuntimeIdentity{ID: "installation-1", Agents: []RuntimeAgent{{InstallationID: "installation-1", AgentID: "agent-default", IsDefault: true}, {InstallationID: "installation-1", AgentID: "agent-other"}}}, want: "agent-default"},
		{name: "no default", identity: RuntimeIdentity{ID: "installation-1", Agents: []RuntimeAgent{{InstallationID: "installation-1", AgentID: "agent-only"}}}},
		{name: "multiple defaults", identity: RuntimeIdentity{ID: "installation-1", Agents: []RuntimeAgent{{InstallationID: "installation-1", AgentID: "agent-a", IsDefault: true}, {InstallationID: "installation-1", AgentID: "agent-b", IsDefault: true}}}},
		{name: "default for another installation", identity: RuntimeIdentity{ID: "installation-1", Agents: []RuntimeAgent{{InstallationID: "installation-2", AgentID: "agent-other", IsDefault: true}}}},
		{name: "mismatched default alongside assigned default", identity: RuntimeIdentity{ID: "installation-1", Agents: []RuntimeAgent{{InstallationID: "installation-1", AgentID: "agent-a", IsDefault: true}, {InstallationID: "installation-2", AgentID: "agent-other", IsDefault: true}}}},
		{name: "empty default agent ID", identity: RuntimeIdentity{ID: "installation-1", Agents: []RuntimeAgent{{InstallationID: "installation-1", IsDefault: true}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.identity.DefaultAgentID(); got != tc.want {
				t.Fatalf("DefaultAgentID() = %q, want %q", got, tc.want)
			}
		})
	}

	identity := identityFromRoot(&RuntimeIdentity{ID: "installation-1", Agents: []RuntimeAgent{{InstallationID: "installation-1", AgentID: "agent-default", IsDefault: true}}})
	if identity.AgentID != "agent-default" {
		t.Fatalf("runtime identity AgentID = %q, want trusted default", identity.AgentID)
	}
}

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
		case "/api/v1/runtime:heartbeat":
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
