package credrelease

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolve_Success(t *testing.T) {
	var got struct {
		SubjectToken string `json:"subject_token"`
		ConnectorID  string `json:"connector_id"`
		Capability   string `json:"capability"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/connectorCredentials:resolve" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected auth header")
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resolveResponse{Credential: "resolved-credential-value"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	cred, err := client.Resolve(context.Background(), "sub-token-123", "conn-abc", "lead.read")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if cred != "resolved-credential-value" {
		t.Fatalf("expected resolved-credential-value, got %s", cred)
	}
	if got.SubjectToken != "sub-token-123" || got.ConnectorID != "conn-abc" || got.Capability != "lead.read" {
		t.Fatalf("unexpected request body: %+v", got)
	}
}

func TestResolve_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := client.Resolve(context.Background(), "sub-token", "conn", "cap")
	if !errors.Is(err, ErrSubjectUnauthorized) {
		t.Fatalf("expected ErrSubjectUnauthorized, got %v", err)
	}
}

func TestResolve_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := client.Resolve(context.Background(), "sub-token", "conn", "cap")
	if err == nil || errors.Is(err, ErrSubjectUnauthorized) {
		t.Fatalf("expected server error, got %v", err)
	}
}

func TestResolve_EmptyCredential(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resolveResponse{Credential: ""})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := client.Resolve(context.Background(), "sub-token", "conn", "cap")
	if err == nil {
		t.Fatal("expected error for empty credential")
	}
}

func TestResolve_RequestFails(t *testing.T) {
	client := NewClient("http://127.0.0.1:1", "test-token")
	_, err := client.Resolve(context.Background(), "sub-token", "conn", "cap")
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
}
