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
	"github.com/HaikeiLabs/kei-connector-runtime/internal/socket"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/statedir"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
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
	dir, err := os.MkdirTemp(os.TempDir(), "h-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
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
	_, err = (pdpAuthorizer{pdp: local}).Authorize(context.Background(), mcproute.Decision{
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
	if _, err := (pdpAuthorizer{pdp: local}).Authorize(context.Background(), mcproute.Decision{
		SessionID: sessionID, Agent: "test-agent", HarnessKind: "test-harness", ConnectorSlug: "test_slug", Tool: "test_tool",
	}); err != nil {
		t.Fatalf("PDP denied test_slug.test_tool: %v", err)
	}
	// A deny policy surfaces as the ADR-036 §4.5 reason policy_denied.
	_, err = (pdpAuthorizer{pdp: local}).Authorize(context.Background(), mcproute.Decision{
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

// TestMCPRoute_WritesAuditRecordsToTheSpool builds the route through the serve
// wiring: a tools/call writes one §4.9 record to the local audit spool, as a
// decision line the collector parses (ADR-036 §4.9, ADR-022).
func TestMCPRoute_WritesAuditRecordsToTheSpool(t *testing.T) {
	stateDir := t.TempDir()
	now := time.Now().UTC()
	store, err := policybundle.OpenStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(buildMCPDescriptorBundle(t, now, "https://mcp.unresolvable.invalid/mcp"), "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", now); err != nil {
		t.Fatal(err)
	}
	cfg := Config{RuntimeToken: "kh_live_runtime_test_token_1234567890", RuntimeStateDir: stateDir, AuditPath: filepath.Join(t.TempDir(), "audit.jsonl")}
	local := keiruntime.NewLocalPDP(cfg, nil)
	t.Cleanup(local.Close)
	ws := "ws-fixture-0001"
	local.SetIdentity(&keiruntime.Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: &ws, AgentID: "test-agent"})
	sessionID, err := local.Sessions.Create(pdp.Subject{UserID: "test-user", Source: "slack", ExternalID: "U1234", Status: pdp.StatusLinked})
	if err != nil {
		t.Fatal(err)
	}
	route := newMCPRoute(cfg, local)
	key, err := route.keys.Mint(mcproute.Session{Subject: "test-user", Agent: "test-agent", HarnessKind: "claude_code", SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp/other_slug", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test_tool","arguments":{"q":"argument-canary-488"}}}`))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	route.handler.ServeHTTP(httptest.NewRecorder(), req)

	spool := strings.TrimSpace(readSpool(t, cfg.AuditPath))
	if strings.Count(spool, "\n") != 0 || !strings.Contains(spool, `"event":"mcp.tools_call"`) || !strings.Contains(spool, `"reason_code":"connector_not_found"`) {
		t.Fatalf("spool = %s, want one mcp.tools_call connector_not_found record", spool)
	}
	if strings.Contains(spool, "argument-canary-488") || strings.Contains(spool, key) {
		t.Fatalf("spool carries an argument value or the route key: %s", spool)
	}
	for _, field := range []string{`"org_id":"org-fixture-0001"`, `"workspace_id":"ws-fixture-0001"`, `"installation_id":"inst-fixture-0001"`, `"harness_kind":"claude_code"`} {
		if !strings.Contains(spool, field) {
			t.Errorf("spool record lacks %s: %s", field, spool)
		}
	}
	event, ok := keiruntime.ParseAuditLine(spool)
	if !ok || event.ToolName != "mcp:other_slug.test_tool" || event.Decision != "deny" || event.AgentID != "test-agent" {
		t.Fatalf("the collector parses %+v (%v), want the deny decision for mcp:other_slug.test_tool", event, ok)
	}
}

// TestMCPRoute_SubmitsCandidatesToTheControlPlane builds the route through
// the serve wiring: its manifest submitter posts to the configured control
// plane with the runtime token and the identity's org and workspace (ADR-036
// §5.4).
func TestMCPRoute_SubmitsCandidatesToTheControlPlane(t *testing.T) {
	const runtimeToken = "kh_live_runtime_test_token_1234567890"
	var gotPath, gotAuth string
	catalog := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.Method+" "+r.URL.Path, r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(catalog.Close)
	cfg := Config{RuntimeToken: runtimeToken, RuntimeControlPlaneURL: catalog.URL, RuntimeStateDir: t.TempDir()}
	local := keiruntime.NewLocalPDP(cfg, nil)
	t.Cleanup(local.Close)
	ws := "ws-fixture-0001"
	local.SetIdentity(&keiruntime.Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: &ws, AgentID: "test-agent"})

	route := newMCPRoute(cfg, local)
	if route.submitter == nil {
		t.Fatal("the route has no manifest submitter")
	}
	tool := json.RawMessage(`{"name":"test_tool","description":"","inputSchema":{"type":"object"}}`)
	if err := route.submitter.Submit(context.Background(), "conn-mcp-1", "sha256:0000000000000000000000000000000000000000000000000000000000000000", []json.RawMessage{tool}); err != nil {
		t.Fatal(err)
	}
	if gotPath != "POST /api/v1/organizations/org-fixture-0001/workspaces/ws-fixture-0001/data-connectors/conn-mcp-1/tool-manifests" || gotAuth != "Bearer "+runtimeToken {
		t.Fatalf("submitted %s with %q", gotPath, gotAuth)
	}

	if newMCPRoute(Config{RuntimeToken: runtimeToken}, local).submitter != nil {
		t.Fatal("a route without a control plane URL must not submit")
	}
}
