package connectorruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
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
	"github.com/HaikeiLabs/kei-connector-runtime/internal/socket"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/statedir"
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
	resp, err = client.Get("http://localhost/v1/model-config")
	if err != nil {
		t.Fatalf("unauthenticated GET /v1/model-config over Unix socket: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET /v1/model-config status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
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

func TestServeDoesNotServeMCPRoute(t *testing.T) {
	tempDir := shortSocketTempDir(t)
	socketPath := filepath.Join(tempDir, "runtime.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	finished := make(chan struct{})

	// Pick a free loopback port for the (removed) MCP listener. On main
	// configFromEnv would read KEI_PROXY_MCP_LISTEN_ADDR and start a second
	// listener here; on this branch the env var is silently ignored.
	mcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mcpAddr := mcpListener.Addr().String()
	mcpListener.Close()

	// Pre-bind to get a deterministic listen address.
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpAddr := tcpListener.Addr().String()
	tcpListener.Close()

	// Configure via configFromEnv so the test fails on main where
	// KEI_PROXY_MCP_LISTEN_ADDR is still wired.
	restore := setenv(t, "KEI_PROXY_MCP_LISTEN_ADDR", mcpAddr)
	defer restore()
	restore = setenv(t, "KEI_RUNTIME_TOKEN", "kh_live_12345678901234567890")
	defer restore()
	restore = setenv(t, "KEI_RUNTIME_STATE_DIR", tempDir)
	defer restore()

	cfg := configFromEnv()

	go func() {
		defer close(finished)
		done <- runServeContext(ctx, cfg, socketPath, tcpAddr)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
		}
	})

	// Wait for the daemon to be ready.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, err = http.Get("http://" + tcpAddr + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("TCP listener not reachable: %v", err)
	}

	// The MCP listen address must NOT be listening — the MCP route is
	// removed. On main this would succeed (a separate MCP listener exists).
	dialer := net.Dialer{Timeout: 500 * time.Millisecond}
	conn, dialErr := dialer.DialContext(ctx, "tcp", mcpAddr)
	if dialErr == nil {
		conn.Close()
		t.Fatalf("MCP listener is active on %s but should be removed", mcpAddr)
	}

	// The main TCP listener returns 404 for /mcp/test.
	resp, err := http.Get("http://" + tcpAddr + "/mcp/test")
	if err != nil {
		t.Fatalf("GET /mcp/test: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /mcp/test status = %d, want 404", resp.StatusCode)
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("runServeContext exit = %d, want 0", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runtime did not stop")
	}
}

func TestPiAuthorizeDecisionUsesDefaultSpoolAndShipsDigestOnly(t *testing.T) {
	var shipped string
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/runtime/audit:flush" {
			t.Errorf("flush path = %q", r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read flush body: %v", err)
		}
		shipped = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"upserted":1,"received":1,"skipped":0}`)
	}))
	defer controlPlane.Close()

	stateDir := t.TempDir()
	cfg := Config{
		RuntimeToken:           "kh_live_runtime_token_1234567890",
		RuntimeControlPlaneURL: controlPlane.URL,
		RuntimeStateDir:        stateDir,
		AuditMaxBytes:          defaultAuditMaxBytes,
	}
	local, err := newServeLocalPDP(cfg, serveSeams{})
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	_, socketHandler := newServeHandlers(cfg, local)
	req := httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(`{"schema":"kei.authorize-request/v1","tool":"pi.shell","framework":"pi","tool_args_digest":"sha256:0123456789abcdef","resource":"command"}`))
	req.Header.Set("Authorization", "Bearer kh_live_runtime_token_1234567890")
	resp := httptest.NewRecorder()
	socketHandler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("authorize status = %d: %s", resp.Code, resp.Body.String())
	}

	auditPath := filepath.Join(stateDir, "audit", "harness-tool.jsonl")
	spool, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read default decision spool %s: %v", auditPath, err)
	}
	if !strings.Contains(string(spool), `"framework":"pi"`) || !strings.Contains(string(spool), `"tool_name":"pi.shell"`) || !strings.Contains(string(spool), `"tool_args_digest":"sha256:0123456789abcdef"`) {
		t.Fatalf("spool missing Pi decision metadata: %s", spool)
	}
	if strings.Contains(string(spool), "raw command") || strings.Contains(string(spool), `"command":`) {
		t.Fatalf("spool contains raw command data: %s", spool)
	}

	collector := keiruntime.NewCollector(auditPath, keiruntime.NewABACFlushClientFromConfig(cfg, time.Second), 100)
	if _, err := collector.Run(context.Background()); err != nil {
		t.Fatalf("ship decision audit: %v", err)
	}
	if !strings.Contains(shipped, `"framework":"pi"`) || !strings.Contains(shipped, `"tool_name":"pi.shell"`) || !strings.Contains(shipped, `"tool_args_digest":"sha256:0123456789abcdef"`) {
		t.Fatalf("shipped payload missing Pi decision metadata: %s", shipped)
	}
	if strings.Contains(shipped, "raw command") || strings.Contains(shipped, `"command":`) {
		t.Fatalf("shipped payload contains raw command data: %s", shipped)
	}
}

func TestPiAuthorizeAppendFailureIsLoggedWithoutDecisionPayload(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stateDir, "audit"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		RuntimeToken:           "kh_live_runtime_token_1234567890",
		RuntimeControlPlaneURL: "https://kei.example",
		RuntimeStateDir:        stateDir,
		AuditMaxBytes:          defaultAuditMaxBytes,
	}
	local, err := newServeLocalPDP(cfg, serveSeams{})
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	_, socketHandler := newServeHandlers(cfg, local)

	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previousLogger)

	req := httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(`{"schema":"kei.authorize-request/v1","tool":"pi.shell","framework":"pi","tool_args_digest":"sha256:0123456789abcdef"}`))
	req.Header.Set("Authorization", "Bearer kh_live_runtime_token_1234567890")
	resp := httptest.NewRecorder()
	socketHandler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("authorize status = %d: %s", resp.Code, resp.Body.String())
	}
	logOutput := logs.String()
	if !strings.Contains(logOutput, "runtime decision audit append failed") || !strings.Contains(logOutput, filepath.Join(stateDir, "audit", "harness-tool.jsonl")) {
		t.Fatalf("append failure not observable in safe diagnostic: %s", logOutput)
	}
	if strings.Contains(logOutput, "sha256:0123456789abcdef") || strings.Contains(logOutput, `"tool_name"`) || strings.Contains(logOutput, `"command":`) {
		t.Fatalf("audit error log leaked decision payload: %s", logOutput)
	}
}

func TestDefaultAuditPathUsesConfiguredPlatformStateDirectory(t *testing.T) {
	t.Setenv("KEI_RUNTIME_STATE_DIR", "")
	t.Setenv("KEI_PROXY_AUDIT", "")
	cfg := configFromEnv()
	wantStateDir := statedir.DefaultPathOS()
	if cfg.RuntimeStateDir != wantStateDir {
		t.Fatalf("runtime state dir = %q, want platform default %q", cfg.RuntimeStateDir, wantStateDir)
	}
	wantAuditPath := filepath.Join(wantStateDir, "audit", "harness-tool.jsonl")
	if got := keiruntime.ResolveAuditPath(cfg.AuditPath, cfg.RuntimeStateDir); got != wantAuditPath {
		t.Fatalf("default audit path = %q, want %q", got, wantAuditPath)
	}
	override := filepath.Join(t.TempDir(), "explicit-audit.jsonl")
	if got := keiruntime.ResolveAuditPath(override, cfg.RuntimeStateDir); got != override {
		t.Fatalf("explicit audit override = %q, want %q", got, override)
	}
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
		want := filepath.Join(t.TempDir(), "test-runtime.sock")
		t.Setenv("KEI_RUNTIME_SOCKET_PATH", want)
		if got := runtimeSocketPathFromEnv(); got != want {
			t.Fatalf("runtimeSocketPathFromEnv() = %q", got)
		}
	})
}

type contextBlockingFlushClient struct {
	calls   atomic.Int32
	started chan struct{}
}

func (f *contextBlockingFlushClient) Flush(ctx context.Context, _ []keiruntime.DecisionEvent) (keiruntime.DecisionFlushResult, error) {
	f.calls.Add(1)
	select {
	case f.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return keiruntime.DecisionFlushResult{}, ctx.Err()
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

	request := httptest.NewRequest(http.MethodGet, "/v1/model-config", nil)
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
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/model-config", nil))

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
func TestHandleModelConfig(t *testing.T) {
	cfg := Config{
		RuntimeToken:           "kh_live_12345678901234567890",
		RuntimeControlPlaneURL: "http://127.0.0.1:1",
	}

	t.Run("runtime_not_configured", func(t *testing.T) {
		h := &runtimeHTTPHandler{
			cfg:      Config{},
			profiles: fakeRuntimeProfiles{},
			client:   &http.Client{Timeout: time.Second},
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/model-config", nil)
		req.Header.Set("Authorization", "Bearer kh_live_12345678901234567890")
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
		}
	})

	t.Run("unauthorized", func(t *testing.T) {
		h := &runtimeHTTPHandler{
			cfg:      cfg,
			profiles: fakeRuntimeProfiles{},
			client:   &http.Client{Timeout: time.Second},
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/model-config", nil)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
		}
	})

	t.Run("no_profile", func(t *testing.T) {
		h := &runtimeHTTPHandler{
			cfg:      cfg,
			profiles: fakeRuntimeProfiles{assignedErr: errors.New("no profile assigned")},
			client:   &http.Client{Timeout: time.Second},
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/model-config", nil)
		req.Header.Set("Authorization", "Bearer kh_live_12345678901234567890")
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
		}
		var resp struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Status != "no_profile" {
			t.Fatalf("status = %q, want %q", resp.Status, "no_profile")
		}
	})

	t.Run("profile_revoked", func(t *testing.T) {
		h := &runtimeHTTPHandler{
			cfg: cfg,
			profiles: fakeRuntimeProfiles{assigned: &ModelProfile{
				ProfileID:    "p1",
				DefaultModel: "gpt-4",
				Endpoint:     "https://api.openai.com",
				Status:       "revoked",
			}},
			client: &http.Client{Timeout: time.Second},
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/model-config", nil)
		req.Header.Set("Authorization", "Bearer kh_live_12345678901234567890")
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
		}
		var resp struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Status != "profile_revoked" {
			t.Fatalf("status = %q, want %q", resp.Status, "profile_revoked")
		}
	})

	t.Run("success_no_credential", func(t *testing.T) {
		h := &runtimeHTTPHandler{
			cfg: cfg,
			profiles: fakeRuntimeProfiles{assigned: &ModelProfile{
				ProfileID:    "p1",
				DefaultModel: "gpt-4",
				Endpoint:     "https://api.openai.com",
				Status:       "active",
				AuthType:     "none",
			}},
			client: &http.Client{Timeout: time.Second},
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/model-config", nil)
		req.Header.Set("Authorization", "Bearer kh_live_12345678901234567890")
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
		}
		var resp struct {
			Model      string `json:"model"`
			Endpoint   string `json:"endpoint"`
			Credential string `json:"credential"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Model != "gpt-4" {
			t.Fatalf("model = %q, want %q", resp.Model, "gpt-4")
		}
		if resp.Endpoint != "https://api.openai.com" {
			t.Fatalf("endpoint = %q, want %q", resp.Endpoint, "https://api.openai.com")
		}
		if resp.Credential != "" {
			t.Fatalf("credential = %q, want empty string", resp.Credential)
		}
	})

	t.Run("success_credential_from_secret", func(t *testing.T) {
		h := &runtimeHTTPHandler{
			cfg: cfg,
			profiles: fakeRuntimeProfiles{assigned: &ModelProfile{
				ProfileID:     "p1",
				DefaultModel:  "gpt-4",
				Endpoint:      "https://api.openai.com",
				Status:        "active",
				AuthType:      "api_key",
				SecretRef:     "",
				SecretBackend: "",
			}},
			client: &http.Client{Timeout: time.Second},
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/model-config", nil)
		req.Header.Set("Authorization", "Bearer kh_live_12345678901234567890")
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
		}
		var resp struct {
			Model      string `json:"model"`
			Endpoint   string `json:"endpoint"`
			Credential string `json:"credential"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Model != "gpt-4" {
			t.Fatalf("model = %q, want %q", resp.Model, "gpt-4")
		}
		if resp.Endpoint != "https://api.openai.com" {
			t.Fatalf("endpoint = %q, want %q", resp.Endpoint, "https://api.openai.com")
		}
		if resp.Credential != "" {
			t.Fatalf("credential = %q, want empty string (no SecretRef)", resp.Credential)
		}
	})

	t.Run("credential_unavailable", func(t *testing.T) {
		h := &runtimeHTTPHandler{
			cfg: cfg,
			profiles: fakeRuntimeProfiles{assigned: &ModelProfile{
				ProfileID:     "p1",
				DefaultModel:  "gpt-4",
				Endpoint:      "https://api.openai.com",
				Status:        "active",
				AuthType:      "api_key",
				SecretRef:     "nonexistent",
				SecretBackend: "file",
			}},
			client: &http.Client{Timeout: time.Second},
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/model-config", nil)
		req.Header.Set("Authorization", "Bearer kh_live_12345678901234567890")
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusInternalServerError, rec.Body.String())
		}
	})
}

// setenv sets an environment variable for the lifetime of a test and returns
// a restore function. The test must call the restore (typically via defer).
func setenv(t *testing.T, key, value string) func() {
	t.Helper()
	orig, ok := os.LookupEnv(key)
	if err := os.Setenv(key, value); err != nil {
		t.Fatalf("setenv(%q): %v", key, err)
	}
	if ok {
		return func() { os.Setenv(key, orig) }
	}
	return func() { os.Unsetenv(key) }
}

func shortSocketTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(os.TempDir(), "h-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
