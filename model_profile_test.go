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

func TestRunModelProfilesListsAssignedProfiles(t *testing.T) {
	const agentID = "00000000-0000-0000-0000-000000000038"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/runtime/model-profiles" || r.URL.Query().Get("agent_id") != agentID {
			t.Fatalf("request = %s, want list scoped to agent", r.URL.String())
		}
		_, _ = w.Write([]byte(`{"model_profiles":[{"profile_id":"00000000-0000-0000-0000-000000000039","display_name":"Test","default_model":"model","endpoint":"https://models.example.test","auth_type":"none","status":"active","is_default":true}]}`))
	}))
	defer server.Close()
	setModelProfileRuntimeEnv(t, server.URL)
	if code := runModelProfiles([]string{"--agent-id", agentID}); code != 0 {
		t.Fatalf("runModelProfiles() = %d, want 0", code)
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

	if code := runModelProfile([]string{"--agent-id", agentID}); code != 0 {
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

func TestRunModelProfileSelectsAssignedProfileByID(t *testing.T) {
	const agentID = "00000000-0000-0000-0000-000000000033"
	const profileID = "00000000-0000-0000-0000-000000000031"
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/api/v1/runtime/model-profiles/"+profileID || r.URL.Query().Get("agent_id") != agentID {
			t.Fatalf("request = %s, want profile lookup scoped to agent", r.URL.String())
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"profile_id": profileID,
			"org_id":     "00000000-0000-0000-0000-000000000032",
			"agent_id":   agentID,
			"is_default": false,
			"status":     "active",
		})
	}))
	defer server.Close()
	setModelProfileRuntimeEnv(t, server.URL)

	if code := runModelProfile([]string{"--agent-id", agentID, "--profile-id", profileID}); code != 0 {
		t.Fatalf("runModelProfile() = %d, want 0", code)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1", requests)
	}
}

func setModelProfileRuntimeEnv(t *testing.T, controlPlaneURL string) {
	t.Helper()
	t.Setenv("KEI_RUNTIME_TOKEN", "runtime-token")
	t.Setenv("KEI_RUNTIME_CONTROL_PLANE_URL", controlPlaneURL)
	t.Setenv("KEI_MODEL_PROFILE_ID", "")
}
