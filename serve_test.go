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
	"github.com/HaikeiLabs/kei-connector-runtime/internal/mcproute"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/socket"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/statedir"
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

func TestServeMCPListener(t *testing.T) {
	t.Run("loopback starts and serves", func(t *testing.T) {
		tempDir := shortSocketTempDir(t)
		socketPath := filepath.Join(tempDir, "runtime.sock")
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan int, 1)
		finished := make(chan struct{})

		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		mcpAddr := l.Addr().String()
		l.Close()

		cfg := Config{
			RuntimeToken:           "kh_live_12345678901234567890",
			RuntimeControlPlaneURL: "http://127.0.0.1:1",
			MCPListenAddr:          mcpAddr,
		}
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
		})

		var resp *http.Response
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			resp, err = http.Get("http://" + mcpAddr + "/mcp/test")
			if err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("MCP listener not reachable: %v", err)
		}
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("MCP GET /mcp/test status = %d, want 405", resp.StatusCode)
		}
		resp.Body.Close()

		cancel()
		select {
		case code := <-done:
			if code != 0 {
				t.Fatalf("runServeContext exit = %d, want 0", code)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("runtime did not stop")
		}
	})

	t.Run("non-loopback rejected", func(t *testing.T) {
		tempDir := shortSocketTempDir(t)
		socketPath := filepath.Join(tempDir, "runtime.sock")
		cfg := Config{
			RuntimeToken:           "kh_live_12345678901234567890",
			RuntimeControlPlaneURL: "http://127.0.0.1:1",
			MCPListenAddr:          "0.0.0.0:8086",
		}

		done := make(chan int, 1)
		go func() {
			done <- runServeContext(context.Background(), cfg, socketPath, "127.0.0.1:0")
		}()

		select {
		case code := <-done:
			if code != 1 {
				t.Fatalf("runServeContext with non-loopback MCP addr = %d, want 1", code)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("runServeContext did not exit")
		}
	})
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

func TestPiAuthorizeDecisionUsesDefaultSpoolAndShipsDigestOnly(t *testing.T) {
	var shipped string
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/runtime/audit/flush" {
			t.Errorf("flush path = %q", r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read flush body: %v", err)
		}
		shipped = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"upserted":1}`)
	}))
	defer controlPlane.Close()

	stateDir := t.TempDir()
	cfg := Config{
		RuntimeToken:           "kh_live_runtime_token_1234567890",
		RuntimeControlPlaneURL: controlPlane.URL,
		RuntimeStateDir:        stateDir,
		AuditMaxBytes:          defaultAuditMaxBytes,
	}
	local, _, err := newServeLocalPDP(cfg, serveSeams{})
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
	local, _, err := newServeLocalPDP(cfg, serveSeams{})
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
	local, _, err := newServeLocalPDP(cfg, serveSeams{})
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

func TestMCPRoute_DeniedWithoutPolicyBundle(t *testing.T) {
	const runtimeToken = "kh_live_runtime_test_token_1234567890"
	local := keiruntime.NewLocalPDP(Config{RuntimeToken: runtimeToken}, nil)

	sessionID, err := local.Sessions.Create(pdp.Subject{
		UserID: "test-user", Source: "slack", ExternalID: "U1234", Status: pdp.StatusLinked,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Without a policy bundle the PDP denies every MCP tool call.
	err = (pdpAuthorizer{pdp: local}).Authorize(context.Background(), mcproute.Decision{
		SessionID: sessionID, Agent: "test-agent", HarnessKind: "test-harness", ConnectorSlug: "test-slug", Tool: "test-tool",
	})
	var permErr *mcproute.PermissionError
	if !errors.As(err, &permErr) || permErr.Reason != "policy_bundle_missing" {
		t.Fatalf("err = %v, want PermissionError policy_bundle_missing", err)
	}
}

func TestMCPRoute_PolicyBundleDecidesMCPCalls(t *testing.T) {
	const runtimeToken = "kh_live_runtime_test_token_1234567890"
	stateDir := t.TempDir()

	now := time.Now().UTC()
	bundle := buildMCPAllowBundle(t, now)
	store, err := policybundle.OpenStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(bundle, "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", now); err != nil {
		t.Fatal(err)
	}

	local := keiruntime.NewLocalPDP(Config{RuntimeToken: runtimeToken, RuntimeStateDir: stateDir}, nil)

	sessionID, err := local.Sessions.Create(pdp.Subject{
		UserID: "test-user", Source: "slack", ExternalID: "U1234", Status: pdp.StatusLinked,
	})
	if err != nil {
		t.Fatal(err)
	}

	ws := "ws-fixture-0001"
	local.SetIdentity(&keiruntime.Identity{
		ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: &ws, AgentID: "test-agent",
	})
	t.Cleanup(local.Close)

	// The PDP itself permits the call.
	if err := (pdpAuthorizer{pdp: local}).Authorize(context.Background(), mcproute.Decision{
		SessionID: sessionID, Agent: "test-agent", HarnessKind: "test-harness", ConnectorSlug: "test_slug", Tool: "test_tool",
	}); err != nil {
		t.Fatalf("PDP denied test_slug.test_tool: %v", err)
	}
	// A deny policy surfaces as the ADR-036 §4.5 reason policy_denied.
	err = (pdpAuthorizer{pdp: local}).Authorize(context.Background(), mcproute.Decision{
		SessionID: sessionID, Agent: "test-agent", HarnessKind: "test-harness", ConnectorSlug: "test_slug", Tool: "blocked_tool",
	})
	var permErr *mcproute.PermissionError
	if !errors.As(err, &permErr) || permErr.Reason != "policy_denied" {
		t.Fatalf("deny policy: err = %v, want PermissionError policy_denied", err)
	}
}

// buildMCPAllowBundle builds a schema-compliant v2 bundle with
// harness_policies that permit test_slug.test_tool unconditionally and a
// bundle identity matching the test session (slack / U1234 / test-user).
func buildMCPAllowBundle(t *testing.T, now time.Time) []byte {
	t.Helper()

	doc := map[string]any{
		"schema": "kei.policy-bundle/v2", "bundle_id": "bundle-mcp-v2", "bundle_version": 2, "policy_revision": 7,
		"issuer": policybundle.Issuer,
		"audience": map[string]any{
			"installation_id": "inst-fixture-0001",
			"org_id":          "org-fixture-0001",
			"workspace_id":    "ws-fixture-0001",
		},
		"issued_at":          now.UTC().Format(time.RFC3339Nano),
		"not_after":          now.Add(12 * time.Hour).UTC().Format(time.RFC3339Nano),
		"refresh":            map[string]any{"poll_interval_seconds": 60, "stale_after_seconds": 300},
		"subject_resolution": map[string]any{"mode": "bundle", "max_cache_seconds": 30},
		"policy_set": map[string]any{
			"schema": "kei.policy-set/v2", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001",
			"match_semantics": "kei.match/v2",
			"evaluation":      map[string]any{"precedence": []string{"priority_desc", "deny_before_permit", "policy_id_asc"}, "checks": "per_capability_first_match_and", "default": "deny"},
			"tools":           []any{}, "checks": []any{}, "tool_policies": []any{},
			"harness_match_semantics": "kei.harness-match/v1",
			"harness_policies": []any{
				map[string]any{
					"policy_id":   "pol-mcp-allow-all",
					"name":        "mcp-allow-test",
					"src_pattern": "*",
					"dst_pattern": "mcp:test_slug.test_tool",
					"action":      "permit",
					"priority":    50,
					"scope":       map[string]any{"org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "agent_id": nil},
				},
				map[string]any{
					"policy_id":   "pol-mcp-deny-blocked",
					"name":        "mcp-deny-blocked",
					"src_pattern": "*",
					"dst_pattern": "mcp:test_slug.blocked_tool",
					"action":      "deny",
					"priority":    50,
					"scope":       map[string]any{"org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "agent_id": nil},
				},
			},
		},
		"agent_connector_bindings": []any{},
		"identities": []any{
			map[string]any{
				"source":      "slack",
				"external_id": "U1234",
				"user_id":     "test-user",
				"status":      "linked",
				"groups":      []string{},
			},
		},
	}

	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestMCPRoute_SessionEndRevokesRouteKey builds the route through the serve
// wiring: ending the named session must revoke its route keys (ADR-036 §4.4).
func TestMCPRoute_SessionEndRevokesRouteKey(t *testing.T) {
	local := keiruntime.NewLocalPDP(Config{RuntimeToken: "kh_live_runtime_test_token_1234567890"}, nil)
	defer local.Close()
	route := newMCPRoute(Config{}, local)

	sessionID, err := local.Sessions.Create(pdp.Subject{UserID: "test-user", Source: "slack", ExternalID: "U1234", Status: pdp.StatusLinked})
	if err != nil {
		t.Fatal(err)
	}
	other, err := local.Sessions.Create(pdp.Subject{UserID: "test-user", Source: "slack", ExternalID: "U1234", Status: pdp.StatusLinked})
	if err != nil {
		t.Fatal(err)
	}
	key, err := route.keys.Mint(mcproute.Session{Subject: "test-user", Agent: "test-agent", HarnessKind: "claude_code", SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := route.keys.Mint(mcproute.Session{Subject: "test-user", Agent: "test-agent", HarnessKind: "claude_code", SessionID: other})
	if err != nil {
		t.Fatal(err)
	}

	local.Sessions.EndID(sessionID)

	if _, ok := route.keys.Validate(key); ok {
		t.Fatal("route key still validates after its session ended")
	}
	if _, ok := route.keys.Validate(otherKey); !ok {
		t.Fatal("another session's route key was revoked")
	}
}

// buildMCPDescriptorBundle is buildMCPAllowBundle with the catalog's HAI-570
// connectors section: one mcp connector (slug test_slug) bound to test-agent.
func buildMCPDescriptorBundle(t *testing.T, now time.Time, mcpURL string) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(buildMCPAllowBundle(t, now), &doc); err != nil {
		t.Fatal(err)
	}
	doc["policy_set"].(map[string]any)["connectors"] = []any{map[string]any{
		"id": "conn-mcp-1", "name": "Test MCP", "provider": "test_mcp", "capabilities": []any{},
		"credential_source": "oauth", "account_model": "per_user",
		"kind": "mcp", "slug": "test_slug",
		"mcp": map[string]any{
			"url": mcpURL, "transport": "streamable_http", "auth_method": "oauth",
			"approved_manifest_hash": "sha256:a94748f3bd7e1bc1e46ff952e802378a98249adfd5fcd2677ff48bd0df848dbb",
			"approved_tools":         []any{map[string]any{"name": "test_tool", "tool_hash": "sha256:9e84a27116887ce94c79f25184ee07da9b9dd0288847be9e0ee885fdc61ec537"}},
		},
	}}
	doc["agent_connector_bindings"] = []any{map[string]any{"agent_id": "test-agent", "connector_id": "conn-mcp-1", "capabilities": []any{}}}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestMCPRoute_ReadsDescriptorsFromTheBundle builds the route through the
// serve wiring: connectors, bindings and upstream URLs come from the v2
// bundle's mcp descriptors (ADR-036 §4.3, §4.5 steps 5-6).
func TestMCPRoute_ReadsDescriptorsFromTheBundle(t *testing.T) {
	stateDir := t.TempDir()
	now := time.Now().UTC()
	store, err := policybundle.OpenStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(buildMCPDescriptorBundle(t, now, "https://mcp.unresolvable.invalid/mcp"), "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", now); err != nil {
		t.Fatal(err)
	}
	local := keiruntime.NewLocalPDP(Config{RuntimeToken: "kh_live_runtime_test_token_1234567890", RuntimeStateDir: stateDir}, nil)
	t.Cleanup(local.Close)
	ws := "ws-fixture-0001"
	local.SetIdentity(&keiruntime.Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: &ws, AgentID: "test-agent"})
	sessionID, err := local.Sessions.Create(pdp.Subject{UserID: "test-user", Source: "slack", ExternalID: "U1234", Status: pdp.StatusLinked})
	if err != nil {
		t.Fatal(err)
	}
	route := newMCPRoute(Config{}, local)

	call := func(agent, slug string) string {
		key, err := route.keys.Mint(mcproute.Session{Subject: "test-user", Agent: agent, HarnessKind: "claude_code", SessionID: sessionID})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/mcp/"+slug, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test_tool","arguments":{}}}`))
		req.Header.Set("Authorization", "Bearer "+key)
		req.Host = "127.0.0.1:8086"
		w := httptest.NewRecorder()
		route.handler.ServeHTTP(w, req)
		var resp struct {
			Error *struct {
				Data struct {
					Reason string `json:"reason"`
				} `json:"data"`
			} `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.Error == nil {
			t.Fatalf("want a JSON-RPC error, got %s", w.Body.Bytes())
		}
		return resp.Error.Data.Reason
	}

	if got := call("test-agent", "other_slug"); got != "connector_not_found" {
		t.Fatalf("unknown slug: reason %q, want connector_not_found", got)
	}
	if got := call("other-agent", "test_slug"); got != "connector_not_bound" {
		t.Fatalf("unbound agent: reason %q, want connector_not_bound", got)
	}
	// The bound agent passes steps 5-6 and the route dials the descriptor's
	// mcp.url to verify a listing; that name does not resolve.
	if got := call("test-agent", "test_slug"); got != "upstream_blocked" {
		t.Fatalf("bound agent: reason %q, want upstream_blocked (the descriptor URL was dialed)", got)
	}
}
