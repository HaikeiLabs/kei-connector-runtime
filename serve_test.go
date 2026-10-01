package connectorruntime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/collector"
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

func TestServeUnixSocketHTTPPermissionsAndCleanup(t *testing.T) {
	tempDir := shortSocketTempDir(t)
	socketPath := filepath.Join(tempDir, "runtime.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	finished := make(chan struct{})
	cfg := Config{RuntimeToken: "kh_live_12345678901234567890", RuntimeControlPlaneURL: "http://127.0.0.1:1"}
	go func() {
		defer close(finished)
		done <- runServeContext(ctx, cfg, socketPath, "127.0.0.1:0")
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
		}
		_ = os.Remove(socketPath)
		_ = os.RemoveAll(tempDir)
	})

	var info os.FileInfo
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		info, err = os.Stat(socketPath)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if info == nil {
		t.Fatal("runtime did not create Unix socket")
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket path mode = %v, want socket", info.Mode())
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("socket permissions = %04o, want 0600", got)
	}

	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	}}
	client := &http.Client{Transport: transport, Timeout: time.Second}
	resp, err := client.Get("http://localhost/readyz")
	if err != nil {
		t.Fatalf("GET /readyz over Unix socket: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /readyz status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	resp, err = client.Get("http://localhost/v1/models")
	if err != nil {
		t.Fatalf("unauthenticated GET /v1/models over Unix socket: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET /v1/models status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	transport.CloseIdleConnections()

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("runServeContext exit = %d, want 0", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runtime did not stop")
	}
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("socket after shutdown: stat err = %v, want not-exist", err)
	}
}

func shortSocketTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "h201-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestRuntimeSocketPathDefaultAndOverride(t *testing.T) {
	t.Setenv("KEI_RUNTIME_SOCKET_PATH", "")
	if got := runtimeSocketPathFromEnv(); got != "/run/kei-proxy/runtime.sock" {
		t.Fatalf("default socket path = %q", got)
	}
	t.Setenv("KEI_RUNTIME_SOCKET_PATH", "/tmp/test-runtime.sock")
	if got := runtimeSocketPathFromEnv(); got != "/tmp/test-runtime.sock" {
		t.Fatalf("configured socket path = %q", got)
	}
}

type contextBlockingFlushClient struct {
	calls   atomic.Int32
	started chan struct{}
}

func (f *contextBlockingFlushClient) Flush(ctx context.Context, _ []DecisionEvent) (int, error) {
	f.calls.Add(1)
	select {
	case f.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return 0, ctx.Err()
}

func TestCollectorServiceFinalFlushIsBoundedAndRetainsSpool(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeJSONL(t, path, []DecisionEvent{ev("shutdown-1")})
	fake := &contextBlockingFlushClient{started: make(chan struct{}, 2)}
	audit := NewCollector(path, fake, 100)
	stop := collector.Service{
		Flusher:           audit,
		Path:              path,
		PollInterval:      time.Hour,
		FinalFlushTimeout: 50 * time.Millisecond,
	}.Start(context.Background())
	select {
	case <-fake.started:
	case <-time.After(time.Second):
		t.Fatal("collector did not start its polling flush")
	}
	started := time.Now()
	done := make(chan struct{})
	go func() {
		stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("collector service exceeded bounded final flush")
	}
	if elapsed := time.Since(started); elapsed < 40*time.Millisecond || elapsed > time.Second {
		t.Fatalf("shutdown final flush duration = %s, want approximately 50ms and under 1s", elapsed)
	}
	if got := fake.calls.Load(); got != 2 {
		t.Fatalf("flush calls = %d, want polling attempt plus one final attempt", got)
	}
	segments, err := audit.spool.segments()
	if err != nil {
		t.Fatal(err)
	}
	if len(segments) != 1 {
		t.Fatalf("pending segments after failed final flush = %d, want 1", len(segments))
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

func TestExtractInvokingSubject_Valid(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"tenant object id", "acme-corp/user-123"},
		{"email-like", "user@example.com/admin"},
		{"path-like", "org/team/sub-team"},
		{"with special chars", "org~name/user.name_suffix"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			r.Header.Set(invokingSubjectHeader, tc.value)
			got, err := extractInvokingSubject(r)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.value {
				t.Fatalf("got %q, want %q", got, tc.value)
			}
		})
	}
}

func TestExtractInvokingSubject_Absent(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	got, err := extractInvokingSubject(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestExtractInvokingSubject_Malformed(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"spaces", "user subject"},
		{"control char", "user\tsubject"},
		{"newline", "user\nsubject"},
		{"too long", func() string {
			s := ""
			for i := 0; i <= maxInvokingSubjectLen; i++ {
				s += "a"
			}
			return s
		}()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			r.Header.Set(invokingSubjectHeader, tc.value)
			_, err := extractInvokingSubject(r)
			if err == nil {
				t.Fatal("expected error for malformed subject")
			}
			if err.Error() != "invalid_invoking_subject" {
				t.Fatalf("error message = %q, want %q", err.Error(), "invalid_invoking_subject")
			}
		})
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

func stringPtr(value string) *string { return &value }

func TestRuntimeHTTPHandlerInvokingSubjectAbsent(t *testing.T) {
	const runtimeToken = "kh_live_runtime_test_token_1234567890"
	const subject = "env-user"
	t.Setenv("KEI_PROXY_INVOKING_SUBJECT", subject)

	var providerCalls int
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"completion-1"}`)
	}))
	defer provider.Close()

	handler := &runtimeHTTPHandler{
		cfg: Config{
			RuntimeControlPlaneURL: "http://control-plane.test",
			RuntimeToken:           runtimeToken,
		},
		profiles: fakeRuntimeProfiles{profile: &ModelProfile{ProfileID: "profile-1", Endpoint: provider.URL, DefaultModel: "m1", Status: "active"}},
		client:   &http.Client{Timeout: time.Second},
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"profile-1"}`))
	request.Header.Set("Authorization", "Bearer "+runtimeToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden || providerCalls != 0 {
		t.Fatalf("cold runtime must deny locally before provider dispatch: status=%d calls=%d body=%s", response.Code, providerCalls, response.Body.String())
	}
}

func TestRuntimeHTTPHandlerInvokingSubjectHeaderPassedToABAC(t *testing.T) {
	const runtimeToken = "kh_live_runtime_test_token_1234567890"
	const headerSubject = "acme/end-user-42"

	var providerCalls int
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"completion-1"}`)
	}))
	defer provider.Close()

	handler := &runtimeHTTPHandler{
		cfg: Config{
			RuntimeControlPlaneURL: "http://control-plane.test",
			RuntimeToken:           runtimeToken,
		},
		profiles: fakeRuntimeProfiles{profile: &ModelProfile{ProfileID: "profile-1", Endpoint: provider.URL, DefaultModel: "m1", Status: "active"}},
		client:   &http.Client{Timeout: time.Second},
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"profile-1"}`))
	request.Header.Set("Authorization", "Bearer "+runtimeToken)
	request.Header.Set(invokingSubjectHeader, headerSubject)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden || providerCalls != 0 {
		t.Fatalf("cold runtime must deny locally before provider dispatch: status=%d calls=%d body=%s", response.Code, providerCalls, response.Body.String())
	}
}

func TestRuntimeHTTPHandlerInvokingSubjectMalformedReturns400(t *testing.T) {
	const runtimeToken = "kh_live_runtime_test_token_1234567890"

	var providerCalls int
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalls++
	}))
	defer provider.Close()

	handler := &runtimeHTTPHandler{
		cfg: Config{
			RuntimeControlPlaneURL: "http://control-plane.test",
			RuntimeToken:           runtimeToken,
		},
		profiles: fakeRuntimeProfiles{profile: &ModelProfile{ProfileID: "profile-1", Endpoint: provider.URL, DefaultModel: "m1", Status: "active"}},
		client:   &http.Client{Timeout: time.Second},
	}

	badValue := "invalid subject with spaces"
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"profile-1"}`))
	request.Header.Set("Authorization", "Bearer "+runtimeToken)
	request.Header.Set(invokingSubjectHeader, badValue)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Error.Code != "invalid_invoking_subject" {
		t.Fatalf("error code = %q, want %q", body.Error.Code, "invalid_invoking_subject")
	}
	if strings.Contains(response.Body.String(), badValue) {
		t.Fatal("response must not echo the malformed header value")
	}
	if providerCalls != 0 {
		t.Fatalf("malformed subject reached provider %d times; want 0", providerCalls)
	}
}

func TestRuntimeHTTPHandlerInvokingSubjectWithoutTokenStill401(t *testing.T) {
	const runtimeToken = "kh_live_runtime_test_token_1234567890"

	handler := &runtimeHTTPHandler{
		cfg: Config{
			RuntimeControlPlaneURL: "http://control-plane.test",
			RuntimeToken:           runtimeToken,
		},
		profiles: fakeRuntimeProfiles{profile: &ModelProfile{ProfileID: "profile-1", DefaultModel: "m1", Status: "active"}},
		client:   &http.Client{Timeout: time.Second},
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"profile-1"}`))
	request.Header.Set(invokingSubjectHeader, "tenant/user")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
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
		client:   &http.Client{Timeout: time.Second},
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"profile-1"}`))
	request.Header.Set("Authorization", "Bearer "+config.RuntimeToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("cold local policy must deny before provider dispatch: status=%d body=%s", response.Code, response.Body.String())
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
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/runtime/whoami":
			_ = json.NewEncoder(w).Encode(RuntimeIdentity{ID: "install-1", OrgID: "org-1", WorkspaceID: stringPtr("workspace-1"), Platform: "discord", Status: "active", BindingStatus: "verified"})
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
			var request struct {
				HarnessToken    string   `json:"harness_token"`
				Action          string   `json:"action"`
				Resource        string   `json:"resource"`
				Resources       []string `json:"resources"`
				AgentID         string   `json:"agent_id"`
				UserID          string   `json:"user_id"`
				InvokingSubject string   `json:"invoking_subject"`
				Framework       string   `json:"framework"`
			}
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

	if response.Code != http.StatusForbidden {
		t.Fatalf("missing local policy bundle should deny: status=%d body=%s", response.Code, response.Body.String())
	}
	if profileCalls != 1 || authorizeCalls != 0 || providerCalls != 0 {
		t.Fatalf("calls profile=%d authorize=%d provider=%d; local policy must avoid catalog decision", profileCalls, authorizeCalls, providerCalls)
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
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/runtime/whoami" {
			_ = json.NewEncoder(w).Encode(RuntimeIdentity{ID: "install-1", OrgID: "org-1", WorkspaceID: stringPtr("workspace-1"), Platform: "discord", Status: "active", BindingStatus: "verified"})
			return
		}
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
			var request struct {
				HarnessToken    string   `json:"harness_token"`
				Action          string   `json:"action"`
				Resource        string   `json:"resource"`
				Resources       []string `json:"resources"`
				AgentID         string   `json:"agent_id"`
				UserID          string   `json:"user_id"`
				InvokingSubject string   `json:"invoking_subject"`
				Framework       string   `json:"framework"`
			}
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
	if authorizeCalls != 0 || providerCalls != 0 {
		t.Fatalf("calls authorize=%d provider=%d, want no catalog decision and no provider calls", authorizeCalls, providerCalls)
	}
}
