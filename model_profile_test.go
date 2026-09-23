package main

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
