package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

type fakeRuntimeProfiles struct {
	profile *ModelProfile
}

func (f fakeRuntimeProfiles) GetRuntimeModelProfile(context.Context, string) (*ModelProfile, error) {
	return f.profile, nil
}
func (f fakeRuntimeProfiles) GetRuntimeDefaultModelProfile(context.Context) (*ModelProfile, error) {
	return f.profile, nil
}
func (f fakeRuntimeProfiles) GetRuntimeAssignedModelProfile(context.Context) (*ModelProfile, error) {
	return f.profile, nil
}

type fakeRuntimeABAC struct {
	request AuthorizeRequest
}

func (f *fakeRuntimeABAC) Authorize(_ context.Context, request AuthorizeRequest) (*AuthorizeResponse, error) {
	f.request = request
	return &AuthorizeResponse{Decision: "allow"}, nil
}
func (f *fakeRuntimeABAC) InvokeConnector(context.Context, ConnectorInvokeRequest) (*ConnectorInvokeResponse, error) {
	return nil, nil
}

func TestRuntimeHTTPHandlerAuthorizesBeforeProviderCall(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/chat/completions" {
			t.Fatalf("provider request = %s %s", r.Method, r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"model":"workspace-default"}` {
			t.Fatalf("provider body = %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"completion-1"}`)
	}))
	defer provider.Close()

	t.Setenv("KEI_PROXY_INVOKING_SUBJECT", "user-1")
	fakeABAC := &fakeRuntimeABAC{}
	config := Config{
		RuntimeControlPlaneURL: "http://control-plane.test",
		RuntimeToken:           "kh_live_runtime_test_token_1234567890",
		RuntimeVersion:         "test",
	}
	handler := &runtimeHTTPHandler{
		cfg:      config,
		profiles: fakeRuntimeProfiles{profile: &ModelProfile{ProfileID: "profile-1", Endpoint: provider.URL, Status: "active"}},
		abac:     fakeABAC,
		client:   &http.Client{Timeout: time.Second},
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"workspace-default"}`))
	request.Header.Set("Authorization", "Bearer "+config.RuntimeToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if fakeABAC.request.Action != "model.invoke" || fakeABAC.request.Resource != "model:profile-1" {
		t.Fatalf("authorization request = %+v", fakeABAC.request)
	}
	if fakeABAC.request.HarnessToken != config.RuntimeToken || fakeABAC.request.UserID != "user-1" {
		t.Fatalf("authorization identity = %+v", fakeABAC.request)
	}
}
