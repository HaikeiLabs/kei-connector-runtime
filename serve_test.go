package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRuntimeHTTPHandlerHealthAndReadiness(t *testing.T) {
	handler := newRuntimeHTTPHandler(Config{})

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("health status = %d, want %d", health.Code, http.StatusOK)
	}

	ready := httptest.NewRecorder()
	handler.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness status = %d, want %d", ready.Code, http.StatusServiceUnavailable)
	}
}

func TestRuntimeHTTPHandlerRejectsInvalidToken(t *testing.T) {
	config := Config{
		RuntimeControlPlaneURL: "http://control-plane.test",
		RuntimeToken:           "kh_live_runtime_test_token_1234567890",
	}
	handler := newRuntimeHTTPHandler(config)

	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	request.Header.Set("Authorization", "Bearer wrong-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestRuntimeHTTPHandlerRequiresBearerToken(t *testing.T) {
	config := Config{
		RuntimeControlPlaneURL: "http://control-plane.test",
		RuntimeToken:           "kh_live_runtime_test_token_1234567890",
	}
	handler := newRuntimeHTTPHandler(config)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}
