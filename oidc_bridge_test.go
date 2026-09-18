package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// HAI-15: Test OIDCBridgeClient with cache and singleflight

func TestOIDCBridgeClientGetOAuthTokenSuccess(t *testing.T) {
	// Create a test server that returns a token
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify auth header
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(OAuthTokenResponse{
			AccessToken: "test-token-123",
			TokenType:   "Bearer",
			Provider:    "github",
			Identity:    "user:123",
		})
	}))
	defer server.Close()

	// Create client
	client := NewOIDCBridgeClient(server.URL, "test-secret", time.Second)

	// First call - should fetch from server
	token, err := client.GetOAuthToken(context.Background(), "user1", "github")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token == nil {
		t.Fatal("expected token, got nil")
	}
	if token.AccessToken != "test-token-123" {
		t.Errorf("expected token 'test-token-123', got '%s'", token.AccessToken)
	}

	// Second call - should use cache
	token2, err := client.GetOAuthToken(context.Background(), "user1", "github")
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}
	if token2.AccessToken != "test-token-123" {
		t.Errorf("expected cached token, got '%s'", token2.AccessToken)
	}
}

func TestOIDCBridgeClientNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewOIDCBridgeClient(server.URL, "test-secret", time.Second)

	token, err := client.GetOAuthToken(context.Background(), "user1", "github")
	if err == nil {
		t.Fatal("expected error for 404")
	}
	if err != ErrEnrollmentRequired {
		t.Errorf("expected ErrEnrollmentRequired, got: %v", err)
	}
	if token != nil {
		t.Error("expected nil token for 404")
	}
}

func TestOIDCBridgeClientConflict(t *testing.T) {
	// 409 Conflict - refresh failed, re-enrollment required
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer server.Close()

	client := NewOIDCBridgeClient(server.URL, "test-secret", time.Second)

	token, err := client.GetOAuthToken(context.Background(), "user1", "github")
	if err == nil {
		t.Fatal("expected error for 409")
	}
	if err != ErrEnrollmentRequired {
		t.Errorf("expected ErrEnrollmentRequired for 409, got: %v", err)
	}
	if token != nil {
		t.Error("expected nil token for 409")
	}
}

func TestOIDCBridgeClientBridgeUnreachable(t *testing.T) {
	// Server that doesn't exist - bridge unreachable
	client := NewOIDCBridgeClient("http://localhost:19999", "test-secret", time.Second)

	token, err := client.GetOAuthToken(context.Background(), "user1", "github")
	if err == nil {
		t.Fatal("expected error for unreachable bridge")
	}
	if err != ErrEnrollmentRequired {
		t.Errorf("expected ErrEnrollmentRequired for unreachable, got: %v", err)
	}
	if token != nil {
		t.Error("expected nil token for unreachable")
	}
}

func TestOIDCBridgeClientUnauthorized(t *testing.T) {
	// Server that returns 401 - but this is a config error, not enrollment required
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewOIDCBridgeClient(server.URL, "wrong-secret", time.Second)

	token, err := client.GetOAuthToken(context.Background(), "user1", "github")
	// This should return an error, but not ErrEnrollmentRequired
	// It indicates a misconfiguration
	if err == nil {
		t.Fatal("expected error for 401")
	}
	if token != nil {
		t.Error("expected nil token for 401")
	}
}

func TestOIDCBridgeClientSingleFlight(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		// Add small delay to simulate network
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(OAuthTokenResponse{
			AccessToken: "test-token",
			TokenType:   "Bearer",
			Provider:    "github",
		})
	}))
	defer server.Close()

	client := NewOIDCBridgeClient(server.URL, "test-secret", time.Second)

	// Make 5 concurrent requests - singleflight should ensure only 1 call
	done := make(chan struct{}, 5)
	for i := 0; i < 5; i++ {
		go func() {
			client.GetOAuthToken(context.Background(), "user1", "github")
			done <- struct{}{}
		}()
	}

	// Wait for all to complete
	for i := 0; i < 5; i++ {
		<-done
	}

	// Should only have 1 actual call due to singleflight
	if callCount != 1 {
		t.Errorf("expected 1 server call (singleflight), got %d", callCount)
	}
}
