package main

import (
	"context"
	"encoding/json"
	"errors"
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
	if health.Code != http.StatusServiceUnavailable {
		t.Fatalf("health status = %d, want %d", health.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(health.Body.String(), "runtime_not_configured") {
		t.Fatalf("health body = %s, want runtime_not_configured", health.Body.String())
	}

	ready := httptest.NewRecorder()
	handler.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness status = %d, want %d", ready.Code, http.StatusServiceUnavailable)
	}
}

func TestRuntimeHTTPHandlerHealthProbeProviderHealthy(t *testing.T) {
	var providerCalls int
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalls++
		if r.URL.Path != "/models" {
			t.Errorf("provider path = %s, want /models", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"object":"list","data":[]}`)
	}))
	defer provider.Close()

	handler := &runtimeHTTPHandler{
		cfg: Config{
			RuntimeControlPlaneURL: "http://control-plane.test",
			RuntimeToken:           "kh_live_runtime_test_token_1234567890",
		},
		profiles: fakeRuntimeProfiles{assigned: &ModelProfile{ProfileID: "p1", Endpoint: provider.URL, Status: "active", AuthType: "none"}},
		client:   &http.Client{Timeout: 5 * time.Second},
	}

	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if resp.Code != http.StatusOK {
		t.Fatalf("health status = %d, body = %s", resp.Code, resp.Body.String())
	}
	if providerCalls != 1 {
		t.Fatalf("provider calls = %d, want 1", providerCalls)
	}
}

func TestRuntimeHTTPHandlerHealthProbeProviderUnhealthy(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusServiceUnavailable)
	}))
	defer provider.Close()

	handler := &runtimeHTTPHandler{
		cfg: Config{
			RuntimeControlPlaneURL: "http://control-plane.test",
			RuntimeToken:           "kh_live_runtime_test_token_1234567890",
		},
		profiles: fakeRuntimeProfiles{assigned: &ModelProfile{ProfileID: "p1", Endpoint: provider.URL, Status: "active", AuthType: "none"}},
		client:   &http.Client{Timeout: 5 * time.Second},
	}

	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("health status = %d, want %d", resp.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(resp.Body.String(), "health_provider_unhealthy") {
		t.Fatalf("health body = %s, want health_provider_unhealthy", resp.Body.String())
	}
}

func TestRuntimeHTTPHandlerHealthProbeProviderUnreachable(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	provider.Close()

	handler := &runtimeHTTPHandler{
		cfg: Config{
			RuntimeControlPlaneURL: "http://control-plane.test",
			RuntimeToken:           "kh_live_runtime_test_token_1234567890",
		},
		profiles: fakeRuntimeProfiles{assigned: &ModelProfile{ProfileID: "p1", Endpoint: provider.URL, Status: "active", AuthType: "none"}},
		client:   &http.Client{Timeout: 2 * time.Second},
	}

	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("health status = %d, want %d", resp.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(resp.Body.String(), "health_provider_unreachable") {
		t.Fatalf("health body = %s, want health_provider_unreachable", resp.Body.String())
	}
}

func TestRuntimeHTTPHandlerHealthProbeNoProfile(t *testing.T) {
	handler := &runtimeHTTPHandler{
		cfg: Config{
			RuntimeControlPlaneURL: "http://control-plane.test",
			RuntimeToken:           "kh_live_runtime_test_token_1234567890",
		},
		profiles: fakeRuntimeProfiles{assignedErr: errors.New("no profile assigned")},
		client:   &http.Client{Timeout: 5 * time.Second},
	}

	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("health status = %d, want %d", resp.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(resp.Body.String(), "health_no_profile") {
		t.Fatalf("health body = %s, want health_no_profile", resp.Body.String())
	}
}

func TestRuntimeHTTPHandlerHealthProbeSendsAuthHeader(t *testing.T) {
	var receivedAuth string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"object":"list","data":[]}`)
	}))
	defer provider.Close()

	handler := &runtimeHTTPHandler{
		cfg: Config{
			RuntimeControlPlaneURL: "http://control-plane.test",
			RuntimeToken:           "kh_live_runtime_test_token_1234567890",
		},
		profiles: fakeRuntimeProfiles{assigned: &ModelProfile{
			ProfileID: "p1", Endpoint: provider.URL, Status: "active",
			AuthType: "none", SecretRef: "", SecretBackend: "",
		}},
		client: &http.Client{Timeout: 5 * time.Second},
	}

	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if resp.Code != http.StatusOK {
		t.Fatalf("health status = %d, body = %s", resp.Code, resp.Body.String())
	}
	if receivedAuth != "" {
		t.Fatalf("auth header = %q, want empty for auth_type=none", receivedAuth)
	}
}

func TestRuntimeHTTPHandlerRejectsInvalidToken(t *testing.T) {
	var controlPlaneCalls, providerCalls int
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalls++
	}))
	defer provider.Close()
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		controlPlaneCalls++
	}))
	defer controlPlane.Close()
	config := Config{
		RuntimeControlPlaneURL: controlPlane.URL,
		RuntimeToken:           "kh_live_runtime_test_token_1234567890",
	}
	handler := newRuntimeHTTPHandler(config)

	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"profile-1"}`))
	request.Header.Set("Authorization", "Bearer wrong-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if controlPlaneCalls != 0 || providerCalls != 0 {
		t.Fatalf("invalid token reached control plane %d times and provider %d times; want neither", controlPlaneCalls, providerCalls)
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

func TestRuntimeHTTPHandlerListsAssignedModel(t *testing.T) {
	config := Config{
		RuntimeControlPlaneURL: "http://control-plane.test",
		RuntimeToken:           "kh_live_runtime_test_token_1234567890",
	}
	handler := &runtimeHTTPHandler{
		cfg: config,
		profiles: fakeRuntimeProfiles{profile: &ModelProfile{
			ProfileID:   "profile-1",
			DisplayName: "Workspace model",
			Status:      "active",
		}},
	}

	request := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	request.Header.Set("Authorization", "Bearer "+config.RuntimeToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `"id":"profile-1"`) || !strings.Contains(body, `"name":"Workspace model"`) {
		t.Fatalf("body = %s", body)
	}
}

func TestRuntimeHTTPHandlerDoesNotFallBackToOrganizationDefaultModel(t *testing.T) {
	config := Config{
		RuntimeControlPlaneURL: "http://control-plane.test",
		RuntimeToken:           "kh_live_runtime_test_token_1234567890",
	}
	handler := &runtimeHTTPHandler{
		cfg: config,
		profiles: fakeRuntimeProfiles{defaultProfile: &ModelProfile{
			ProfileID:   "org-default-profile",
			DisplayName: "Organization default",
			Status:      "active",
		}, assignedErr: errors.New("runtime has no active profile assigned to its default agent")},
	}

	request := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	request.Header.Set("Authorization", "Bearer "+config.RuntimeToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	body := response.Body.String()
	if response.Code != http.StatusBadGateway || strings.Contains(body, "org-default-profile") {
		t.Fatalf("status = %d, body = %s", response.Code, body)
	}
}

func TestRuntimeHTTPHandlerRejectsModelOutsideAssignedProfile(t *testing.T) {
	handler := &runtimeHTTPHandler{
		profiles: fakeRuntimeProfiles{assigned: &ModelProfile{ProfileID: "assigned-profile", Status: "active"}},
	}
	if _, err := handler.resolveProfile(context.Background(), "other-profile"); err == nil || !strings.Contains(err.Error(), "not assigned") {
		t.Fatalf("resolveProfile error = %v, want assignment authorization error", err)
	}
}

type fakeRuntimeProfiles struct {
	profile        *ModelProfile
	assigned       *ModelProfile
	assignedErr    error
	defaultProfile *ModelProfile
}

func (f fakeRuntimeProfiles) GetRuntimeModelProfile(context.Context, string) (*ModelProfile, error) {
	return f.profile, nil
}
func (f fakeRuntimeProfiles) GetRuntimeDefaultModelProfile(context.Context) (*ModelProfile, error) {
	if f.defaultProfile != nil {
		return f.defaultProfile, nil
	}
	return f.profile, nil
}
func (f fakeRuntimeProfiles) GetRuntimeAssignedModelProfile(context.Context) (*ModelProfile, error) {
	if f.assigned != nil {
		return f.assigned, nil
	}
	if f.assignedErr != nil {
		return nil, f.assignedErr
	}
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

func TestRuntimeHTTPHandlerInvokesResolvedProfile(t *testing.T) {
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

	config := Config{
		RuntimeControlPlaneURL: "http://control-plane.test",
		RuntimeToken:           "kh_live_runtime_test_token_1234567890",
	}
	handler := &runtimeHTTPHandler{
		cfg:      config,
		profiles: fakeRuntimeProfiles{profile: &ModelProfile{ProfileID: "profile-1", Endpoint: provider.URL, DefaultModel: "workspace-default", Status: "active"}},
		abac:     &fakeRuntimeABAC{},
		client:   &http.Client{Timeout: time.Second},
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"profile-1"}`))
	request.Header.Set("Authorization", "Bearer "+config.RuntimeToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestRuntimeHTTPHandlerAuthorizesAssignedProfileBeforeProviderDispatch(t *testing.T) {
	const runtimeToken = "kh_live_runtime_test_token_1234567890"
	const profileID = "00000000-0000-0000-0000-000000000031"
	const agentID = "00000000-0000-0000-0000-000000000041"
	const subject = "user:runtime-invoker"
	t.Setenv("KEI_PROXY_AGENT_ID", agentID)
	t.Setenv("KEI_PROXY_INVOKING_SUBJECT", subject)

	var providerCalls int
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalls++
		if r.Method != http.MethodPost || r.URL.Path != "/chat/completions" {
			t.Errorf("provider request = %s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode provider request: %v", err)
		} else if body["model"] != "assigned-upstream-model" {
			t.Errorf("provider model = %v, want assigned-upstream-model", body["model"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"completion-1"}`)
	}))
	defer provider.Close()

	var profileCalls, authorizeCalls int
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/runtime/model-profiles/assigned":
			profileCalls++
			if r.Header.Get("Authorization") != "Bearer "+runtimeToken {
				t.Errorf("profile request bearer = %q, want configured runtime token", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"profile_id": profileID, "org_id": "00000000-0000-0000-0000-000000000011", "agent_id": agentID,
				"display_name": "Assigned model", "endpoint": provider.URL, "default_model": "assigned-upstream-model",
				"auth_type": "none", "status": "active",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/authorize":
			authorizeCalls++
			var request AuthorizeRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode authorization request: %v", err)
			}
			if request.HarnessToken != runtimeToken {
				t.Errorf("authorization harness_token = %q, want configured runtime token", request.HarnessToken)
			}
			if request.Action != "model.invoke" || request.Resource != "model:"+profileID {
				t.Errorf("authorization action/resource = %q/%q", request.Action, request.Resource)
			}
			if request.Resources == nil || len(request.Resources) != 1 || request.Resources[0] != "model:"+profileID {
				t.Errorf("authorization resources = %#v", request.Resources)
			}
			if request.AgentID != agentID || request.UserID != subject || request.InvokingSubject != subject {
				t.Errorf("authorization identity claims agent=%q user=%q invoking=%q", request.AgentID, request.UserID, request.InvokingSubject)
			}
			if request.Framework != "openai-http" {
				t.Errorf("authorization framework = %q, want openai-http", request.Framework)
			}
			_ = json.NewEncoder(w).Encode(AuthorizeResponse{Decision: "allow"})
		default:
			t.Errorf("unexpected control-plane request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer controlPlane.Close()

	handler := newRuntimeHTTPHandler(Config{RuntimeControlPlaneURL: controlPlane.URL, RuntimeToken: runtimeToken})
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"`+profileID+`"}`))
	request.Header.Set("Authorization", "Bearer "+runtimeToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if profileCalls != 1 || authorizeCalls != 1 || providerCalls != 1 {
		t.Fatalf("calls profile=%d authorize=%d provider=%d, want 1 each", profileCalls, authorizeCalls, providerCalls)
	}
}

func TestRuntimeHTTPHandlerDeniesBeforeProviderDispatch(t *testing.T) {
	const runtimeToken = "kh_live_runtime_test_token_1234567890"
	const profileID = "00000000-0000-0000-0000-000000000032"
	var providerCalls int
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalls++
	}))
	defer provider.Close()
	var authorizeCalls int
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/runtime/model-profiles/assigned" {
			if r.Header.Get("Authorization") != "Bearer "+runtimeToken {
				t.Errorf("profile request bearer = %q, want configured runtime token", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"profile_id": profileID, "org_id": "00000000-0000-0000-0000-000000000011", "agent_id": "00000000-0000-0000-0000-000000000041",
				"display_name": "Assigned model", "endpoint": provider.URL, "default_model": "upstream-model", "auth_type": "none", "status": "active",
			})
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/authorize" {
			authorizeCalls++
			var request AuthorizeRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode authorization request: %v", err)
			}
			if request.HarnessToken != runtimeToken {
				t.Errorf("authorization harness_token = %q, want configured runtime token", request.HarnessToken)
			}
			_ = json.NewEncoder(w).Encode(AuthorizeResponse{Decision: "deny", Reason: "policy denied"})
			return
		}
		t.Errorf("unexpected control-plane request %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}))
	defer controlPlane.Close()

	handler := newRuntimeHTTPHandler(Config{RuntimeControlPlaneURL: controlPlane.URL, RuntimeToken: runtimeToken})
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"`+profileID+`"}`))
	request.Header.Set("Authorization", "Bearer "+runtimeToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"code":"model_invocation_denied"`) {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if authorizeCalls != 1 || providerCalls != 0 {
		t.Fatalf("calls authorize=%d provider=%d, want authorize once and no provider calls", authorizeCalls, providerCalls)
	}
}
