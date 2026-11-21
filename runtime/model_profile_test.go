package runtime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestControlPlaneModelProfileClient_GetRuntimeDefaultModelProfile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/runtime/model-profiles/default" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer runtime-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"profile_id":    "00000000-0000-0000-0000-000000000001",
			"org_id":        "00000000-0000-0000-0000-000000000002",
			"endpoint":      "https://models.example.test/v1",
			"default_model": "test-model",
			"auth_type":     "none",
			"status":        "active",
		})
	}))
	defer server.Close()

	client := NewControlPlaneModelProfileClient(server.URL, "runtime-token", 0)
	profile, err := client.GetRuntimeDefaultModelProfile(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if profile == nil || profile.DefaultModel != "test-model" {
		t.Fatalf("unexpected profile: %+v", profile)
	}
	if profile.CredentialStoreInstallation != "" || profile.SecretBackend != "" || profile.SecretRef != "" {
		t.Fatalf("keyless profile without store returned credential-store metadata: %+v", profile)
	}
}

func TestControlPlaneModelProfileClient_GetRuntimeAssignedModelProfileForAgent(t *testing.T) {
	const agentID = "00000000-0000-0000-0000-000000000014"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/runtime/model-profiles/assigned" || r.URL.Query().Get("agent_id") != agentID {
			t.Fatalf("request = %s, want assigned?agent_id=%s", r.URL.String(), agentID)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"profile_id": "00000000-0000-0000-0000-000000000015",
			"org_id":     "00000000-0000-0000-0000-000000000016",
			"agent_id":   agentID,
			"status":     "active",
		})
	}))
	defer server.Close()

	client := NewControlPlaneModelProfileClient(server.URL, "runtime-token", 0)
	profile, err := client.GetRuntimeAssignedModelProfileForAgent(context.Background(), agentID)
	if err != nil {
		t.Fatal(err)
	}
	if profile == nil || profile.AgentID != agentID {
		t.Fatalf("unexpected profile: %+v", profile)
	}
}

func TestControlPlaneModelProfileClient_RejectsMismatchedRequestedAgent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"profile_id": "00000000-0000-0000-0000-000000000015",
			"org_id":     "00000000-0000-0000-0000-000000000016",
			"agent_id":   "00000000-0000-0000-0000-000000000017",
			"status":     "active",
		})
	}))
	defer server.Close()
	client := NewControlPlaneModelProfileClient(server.URL, "runtime-token", 0)
	if _, err := client.GetRuntimeAssignedModelProfileForAgent(context.Background(), "00000000-0000-0000-0000-000000000014"); err == nil {
		t.Fatal("expected mismatched agent response to fail")
	}
}

func TestControlPlaneModelProfileClient_GetRuntimeModelProfileForAgent(t *testing.T) {
	const agentID = "00000000-0000-0000-0000-000000000024"
	const profileID = "00000000-0000-0000-0000-000000000025"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/runtime/model-profiles/"+profileID || r.URL.Query().Get("agent_id") != agentID {
			t.Fatalf("request = %s, want profile and agent selector", r.URL.String())
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"profile_id": profileID, "org_id": "00000000-0000-0000-0000-000000000026",
			"agent_id": agentID, "is_default": false, "status": "active",
		})
	}))
	defer server.Close()
	client := NewControlPlaneModelProfileClient(server.URL, "runtime-token", 0)
	profile, err := client.GetRuntimeModelProfileForAgent(context.Background(), profileID, agentID)
	if err != nil || profile == nil || profile.IsDefault {
		t.Fatalf("profile = %+v, err = %v", profile, err)
	}
}

func TestControlPlaneModelProfileClient_ListRuntimeModelProfiles(t *testing.T) {
	const agentID = "00000000-0000-0000-0000-000000000027"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/runtime/model-profiles" || r.URL.Query().Get("agent_id") != agentID {
			t.Fatalf("request = %s, want profile list and agent selector", r.URL.String())
		}
		_, _ = w.Write([]byte(`{"model_profiles":[{"profile_id":"00000000-0000-0000-0000-000000000028","display_name":"Test","default_model":"model","endpoint":"https://models.example.test","auth_type":"api_key","status":"active","is_default":true}]}`))
	}))
	defer server.Close()
	client := NewControlPlaneModelProfileClient(server.URL, "runtime-token", 0)
	profiles, err := client.ListRuntimeModelProfiles(context.Background(), agentID)
	if err != nil || len(profiles.ModelProfiles) != 1 || !profiles.ModelProfiles[0].IsDefault {
		t.Fatalf("profiles = %+v, err = %v", profiles, err)
	}
	encoded, err := json.Marshal(profiles)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret_ref") || strings.Contains(string(encoded), "credential") {
		t.Fatalf("profile list contains credential material: %s", encoded)
	}
}

func TestControlPlaneModelProfileClient_GetRuntimeAssignedModelProfile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/runtime/model-profiles/assigned" {
			t.Fatalf("path = %q, want assigned runtime profile path", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"profile_id":"00000000-0000-0000-0000-000000000002","org_id":"00000000-0000-0000-0000-000000000003","agent_id":"00000000-0000-0000-0000-000000000004","default_model":"assigned-model","status":"active"}`))
	}))
	defer server.Close()

	client := NewControlPlaneModelProfileClient(server.URL, "runtime-token", 0)
	profile, err := client.GetRuntimeAssignedModelProfile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if profile == nil || profile.DefaultModel != "assigned-model" {
		t.Fatalf("unexpected profile: %+v", profile)
	}
}
