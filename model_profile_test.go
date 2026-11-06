package connectorruntime

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRunModelProfileUsesRuntimeAssignedProfileByDefault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/runtime/model-profiles/assigned" {
			t.Fatalf("path = %q, want assigned profile path", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"profile_id":    "00000000-0000-0000-0000-000000000011",
			"org_id":        "00000000-0000-0000-0000-000000000012",
			"agent_id":      "00000000-0000-0000-0000-000000000013",
			"endpoint":      "https://models.example.test/v1",
			"default_model": "assigned-model",
			"auth_type":     "none",
			"status":        "active",
		})
	}))
	defer server.Close()

	t.Setenv("KEI_RUNTIME_TOKEN", "runtime-token")
	t.Setenv("KEI_RUNTIME_CONTROL_PLANE_URL", server.URL)
	t.Setenv("KEI_MODEL_PROFILE_ID", "")

	if code := runModelProfile(nil); code != 0 {
		t.Fatalf("runModelProfile() = %d, want 0", code)
	}
}

func TestRunModelProfileUsesRequestedAgent(t *testing.T) {
	const agentID = "00000000-0000-0000-0000-000000000041"
	const profileID = "00000000-0000-0000-0000-000000000042"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/runtime/model-profiles/assigned" || r.URL.Query().Get("agent_id") != agentID {
			t.Fatalf("request = %s, want assigned?agent_id=%s", r.URL.String(), agentID)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"profile_id": profileID,
			"org_id":     "00000000-0000-0000-0000-000000000043",
			"agent_id":   agentID,
			"status":     "active",
		})
	}))
	defer server.Close()
	setModelProfileRuntimeEnv(t, server.URL)

	if code := runModelProfile([]string{"--agent-id", agentID, "--profile-id", profileID}); code != 0 {
		t.Fatalf("runModelProfile() = %d, want 0", code)
	}
}

func TestRunModelProfileRejectsInvalidAgentID(t *testing.T) {
	setModelProfileRuntimeEnv(t, "http://127.0.0.1:1")
	if code := runModelProfile([]string{"--agent-id", "not-a-uuid"}); code != 2 {
		t.Fatalf("runModelProfile() = %d, want 2", code)
	}
}

func TestRunModelProfileRejectsResponseForDifferentAgent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"profile_id": "00000000-0000-0000-0000-000000000045",
			"org_id":     "00000000-0000-0000-0000-000000000046",
			"agent_id":   "00000000-0000-0000-0000-000000000047",
			"status":     "active",
		})
	}))
	defer server.Close()
	setModelProfileRuntimeEnv(t, server.URL)
	if code := runModelProfile([]string{"--agent-id", "00000000-0000-0000-0000-000000000044"}); code != 1 {
		t.Fatalf("runModelProfile() = %d, want 1", code)
	}
}

func TestRunModelProfileFailsWhenDefaultAgentIsMissing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/runtime/model-profiles/assigned" {
			t.Fatalf("path = %q, want assigned profile path", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"profile_id":"00000000-0000-0000-0000-000000000021","org_id":"00000000-0000-0000-0000-000000000022","status":"active"}`))
	}))
	defer server.Close()
	setModelProfileRuntimeEnv(t, server.URL)

	if code := runModelProfile(nil); code != 1 {
		t.Fatalf("runModelProfile() = %d, want 1", code)
	}
}

func TestRunModelProfileFailsWhenAssignedProfileIsMissing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/runtime/model-profiles/assigned" {
			t.Fatalf("path = %q, want assigned profile path", r.URL.Path)
		}
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}))
	defer server.Close()
	setModelProfileRuntimeEnv(t, server.URL)

	if code := runModelProfile(nil); code != 1 {
		t.Fatalf("runModelProfile() = %d, want 1", code)
	}
}

func TestRunModelProfileAuthorizesExplicitIDAgainstAssignedProfile(t *testing.T) {
	const assignedID = "00000000-0000-0000-0000-000000000031"
	var explicitLookup bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/runtime/model-profiles/assigned":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"profile_id": assignedID,
				"org_id":     "00000000-0000-0000-0000-000000000032",
				"agent_id":   "00000000-0000-0000-0000-000000000033",
				"status":     "active",
			})
		default:
			explicitLookup = true
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	setModelProfileRuntimeEnv(t, server.URL)
	t.Setenv("KEI_MODEL_PROFILE_ID", "")

	if code := runModelProfile([]string{"--profile-id", "00000000-0000-0000-0000-000000000099"}); code != 1 {
		t.Fatalf("runModelProfile() = %d, want 1", code)
	}
	if explicitLookup {
		t.Fatal("explicit ID was looked up without assignment authorization")
	}

	if code := runModelProfile([]string{"--profile-id", assignedID}); code != 0 {
		t.Fatalf("runModelProfile() = %d for assigned ID, want 0", code)
	}
	if explicitLookup {
		t.Fatal("matching assigned ID should not use an unscoped profile lookup")
	}
}

func setModelProfileRuntimeEnv(t *testing.T, controlPlaneURL string) {
	t.Helper()
	t.Setenv("KEI_RUNTIME_TOKEN", "runtime-token")
	t.Setenv("KEI_RUNTIME_CONTROL_PLANE_URL", controlPlaneURL)
	t.Setenv("KEI_MODEL_PROFILE_ID", "")
}
