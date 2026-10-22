package runtime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
