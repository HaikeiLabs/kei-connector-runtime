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
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/collector"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/socket"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

func TestRuntimeHTTPHandlerHealthAndReadiness(t *testing.T) {
	handler := newRuntimeHTTPHandler(Config{}, nil)

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

	authorizeReq, err := http.NewRequest(http.MethodPost, "http://localhost/v1/authorize", strings.NewReader(`{"schema":"kei.authorize-request/v1","tool":"pi.read","resource":"/tmp/file.txt"}`))
	if err != nil {
		t.Fatal(err)
	}
	authorizeReq.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(authorizeReq)
	if err != nil {
		t.Fatalf("unauthenticated POST /v1/authorize over Unix socket: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read local authorize response: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tokenless POST /v1/authorize without an enabled owner session status = %d, want %d: %s", resp.StatusCode, http.StatusUnauthorized, body)
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

func TestSocketAuthorizeUsesOwnerOnlySocketWithoutRuntimeToken(t *testing.T) {
	cfg := Config{
		RuntimeToken:           "kh_live_12345678901234567890",
		RuntimeControlPlaneURL: "http://127.0.0.1:1",
		RuntimeStateDir:        t.TempDir(),
	}
	local, err := newServeLocalPDP(cfg, serveSeams{})
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	tcpHandler, socketHandler := newServeHandlers(cfg, local)
	body := `{"schema":"kei.authorize-request/v1","tool":"pi.read","resource":"/tmp/file.txt"}`

	socketResponse := httptest.NewRecorder()
	socketHandler.ServeHTTP(socketResponse, httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(body)))
	if socketResponse.Code != http.StatusUnauthorized {
		t.Fatalf("tokenless local authorize status = %d, want %d: %s", socketResponse.Code, http.StatusUnauthorized, socketResponse.Body.String())
	}

	tcpResponse := httptest.NewRecorder()
	tcpHandler.ServeHTTP(tcpResponse, httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(body)))
	if tcpResponse.Code != http.StatusNotFound {
		t.Fatalf("TCP authorize route status = %d, want %d", tcpResponse.Code, http.StatusNotFound)
	}

	sessionResponse := httptest.NewRecorder()
	socketHandler.ServeHTTP(sessionResponse, httptest.NewRequest(http.MethodGet, "/v1/session", nil))
	if sessionResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated socket session status = %d, want %d", sessionResponse.Code, http.StatusUnauthorized)
	}
}

func TestRuntimeSocketPathDefaultAndOverride(t *testing.T) {
	t.Run("DefaultPath_linux", func(t *testing.T) {
		if got := socket.DefaultPath("linux"); got != "/run/kei-proxy/runtime.sock" {
			t.Fatalf("DefaultPath(\"linux\") = %q", got)
		}
	})
	t.Run("DefaultPath_darwin", func(t *testing.T) {
		want := filepath.Join(os.TempDir(), "kei-proxy", "runtime.sock")
		if got := socket.DefaultPath("darwin"); got != want {
			t.Fatalf("DefaultPath(\"darwin\") = %q, want %q", got, want)
		}
	})
	t.Run("FromEnv_default", func(t *testing.T) {
		t.Setenv("KEI_RUNTIME_SOCKET_PATH", "")
		if got := runtimeSocketPathFromEnv(); got != socket.DefaultPathOS() {
			t.Fatalf("runtimeSocketPathFromEnv() = %q, want %q", got, socket.DefaultPathOS())
		}
	})
	t.Run("FromEnv_override", func(t *testing.T) {
		t.Setenv("KEI_RUNTIME_SOCKET_PATH", "/tmp/test-runtime.sock")
		if got := runtimeSocketPathFromEnv(); got != "/tmp/test-runtime.sock" {
			t.Fatalf("runtimeSocketPathFromEnv() = %q", got)
		}
	})
}

type contextBlockingFlushClient struct {
	calls   atomic.Int32
	started chan struct{}
}

func (f *contextBlockingFlushClient) Flush(ctx context.Context, _ []keiruntime.DecisionEvent) (int, error) {
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
	writeJSONL(t, path, []keiruntime.DecisionEvent{ev("shutdown-1")})
	fake := &contextBlockingFlushClient{started: make(chan struct{}, 2)}
	audit := keiruntime.NewCollector(path, fake, 100)
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
	dir := filepath.Dir(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	prefix := filepath.Base(path) + "."
	const segDigits = 10
	var segments []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		suffix := e.Name()[len(prefix):]
		if len(suffix) != segDigits {
			continue
		}
		if _, err := strconv.ParseUint(suffix, 10, 64); err != nil {
			continue
		}
		segments = append(segments, e.Name())
	}
	if len(segments) != 1 {
		t.Fatalf("pending segments after failed final flush = %d, want 1; got %v", len(segments), segments)
	}
}

func writeJSONL(t *testing.T, path string, events []keiruntime.DecisionEvent) {
	t.Helper()
	var data []byte
	for _, e := range events {
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		data = append(data, append(line, '\n')...)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write jsonl: %v", err)
	}
}

func ev(spanID string) keiruntime.DecisionEvent {
	return keiruntime.DecisionEvent{SpanID: spanID, InvokingSubject: "user-1", AgentID: "agent-1", Framework: "claude", ToolName: "web_search", Decision: "allow"}
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
			RuntimeControlPlaneURL: "https://control-plane.test",
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
			RuntimeControlPlaneURL: "https://control-plane.test",
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
			RuntimeControlPlaneURL: "https://control-plane.test",
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
			RuntimeControlPlaneURL: "https://control-plane.test",
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
			RuntimeControlPlaneURL: "https://control-plane.test",
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
	handler := newRuntimeHTTPHandler(config, nil)

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
		RuntimeControlPlaneURL: "https://control-plane.test",
		RuntimeToken:           "kh_live_runtime_test_token_1234567890",
	}
	handler := newRuntimeHTTPHandler(config, nil)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestRuntimeHTTPHandlerListsAssignedModel(t *testing.T) {
	config := Config{
		RuntimeControlPlaneURL: "https://control-plane.test",
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
		RuntimeControlPlaneURL: "https://control-plane.test",
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

	var providerCalls int
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"completion-1"}`)
	}))
	defer provider.Close()

	handler := &runtimeHTTPHandler{
		cfg: Config{
			RuntimeControlPlaneURL: "https://control-plane.test",
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

func TestRuntimeHTTPHandlerInvokingSubjectWithoutTokenStill401(t *testing.T) {
	const runtimeToken = "kh_live_runtime_test_token_1234567890"

	handler := &runtimeHTTPHandler{
		cfg: Config{
			RuntimeControlPlaneURL: "https://control-plane.test",
			RuntimeToken:           runtimeToken,
		},
		profiles: fakeRuntimeProfiles{profile: &ModelProfile{ProfileID: "profile-1", DefaultModel: "m1", Status: "active"}},
		client:   &http.Client{Timeout: time.Second},
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"profile-1"}`))
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
		RuntimeControlPlaneURL: "https://control-plane.test",
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
			if request.AgentID != agentID || request.UserID != subject || request.InvokingSubject != "" {
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

	handler := newRuntimeHTTPHandler(Config{RuntimeControlPlaneURL: controlPlane.URL, RuntimeToken: runtimeToken}, nil)
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

	handler := newRuntimeHTTPHandler(Config{RuntimeControlPlaneURL: controlPlane.URL, RuntimeToken: runtimeToken}, nil)
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

func TestRuntimeHTTPHandlerIgnoresInvokingSubjectHeader(t *testing.T) {
	const runtimeToken = "kh_live_runtime_test_token_1234567890"
	stateDir := t.TempDir()
	now := time.Now().UTC()
	mustActivateTestBundle(t, stateDir, now)
	workspace := "ws-fixture-0001"

	var subjectUserID string
	catalog := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/runtime/subject-attributes:resolve" {
			t.Errorf("unexpected catalog request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		var req keiruntime.SubjectResolveRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode subject resolve request: %v", err)
		}
		subjectUserID = req.UserID
		_ = json.NewEncoder(w).Encode(policybundle.Subject{
			Status: "linked_approved", UserID: req.UserID,
			EffectiveGroups: []string{"members"}, OrgRoles: []string{"member"}, MaxAgeSeconds: 60,
		})
	}))
	defer catalog.Close()
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/runtime/whoami":
			_ = json.NewEncoder(w).Encode(RuntimeIdentity{
				ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: &workspace,
				Platform: "discord", Status: "active", BindingStatus: "verified",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/runtime/model-profiles/assigned":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"profile_id":   "00000000-0000-0000-0000-000000000011",
				"org_id":       "00000000-0000-0000-0000-000000000012",
				"agent_id":     "00000000-0000-0000-0000-000000000013",
				"display_name": "Test model", "endpoint": "http://127.0.0.1:1",
				"default_model": "m1", "auth_type": "none", "status": "active",
			})
		default:
			t.Errorf("unexpected control plane request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer controlPlane.Close()

	sessions := pdp.NewSessions()
	if err := sessions.Start(pdp.Subject{UserID: "session-user-42", Status: pdp.StatusLinked}); err != nil {
		t.Fatal(err)
	}

	handler := newRuntimeHTTPHandler(Config{
		RuntimeControlPlaneURL: controlPlane.URL,
		ABACURL:                catalog.URL,
		RuntimeToken:           runtimeToken,
		RuntimeStateDir:        stateDir,
	}, sessions)

	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"00000000-0000-0000-0000-000000000011"}`))
	request.Header.Set("Authorization", "Bearer "+runtimeToken)
	request.Header.Set("X-Kei-Invoking-Subject", "victim")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (model:invoke not in test bundle), body = %s", response.Code, response.Body.String())
	}
	if subjectUserID != "session-user-42" {
		t.Fatalf("subject resolve UserID = %q, want session-user-42 (X-Kei-Invoking-Subject header victim was ignored)", subjectUserID)
	}
}
