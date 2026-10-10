package connectorruntime

import (
	"bytes"
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
	"sync"
	"testing"
	"time"

	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

// fakeControlPlane is the catalog's runtime surface for the serve
// supervisor tests: whoami, heartbeat, and a policy bundle route that has no
// bundle yet. It counts every request it sees.
type fakeControlPlane struct {
	mu              sync.Mutex
	requests        int
	whoamis         int
	heartbeatBodies []map[string]any
	heartbeatStatus int
}

func newFakeControlPlane(t *testing.T) (*fakeControlPlane, *httptest.Server) {
	t.Helper()
	cp := &fakeControlPlane{heartbeatStatus: http.StatusNoContent}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cp.mu.Lock()
		defer cp.mu.Unlock()
		cp.requests++
		switch {
		case r.URL.Path == "/api/v1/runtime/whoami":
			cp.whoamis++
			_ = json.NewEncoder(w).Encode(RuntimeIdentity{ID: "installation-1", OrgID: "org-1", WorkspaceID: strPtr("workspace-1"), Platform: "openwebui", Status: "active", BindingStatus: "verified"})
		case r.URL.Path == "/api/v1/runtime:heartbeat":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			cp.heartbeatBodies = append(cp.heartbeatBodies, body)
			w.WriteHeader(cp.heartbeatStatus)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return cp, server
}

func (cp *fakeControlPlane) counts() (requests, whoamis, heartbeats int) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.requests, cp.whoamis, len(cp.heartbeatBodies)
}

func (cp *fakeControlPlane) setHeartbeatStatus(status int) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.heartbeatStatus = status
}

func eventually(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type serveRun struct {
	socketPath string
	cancel     context.CancelFunc
	code       chan int
}

func supervisedServeConfig(controlPlaneURL, stateDir string) Config {
	return Config{
		RuntimeToken:             heartbeatTestToken,
		RuntimeControlPlaneURL:   controlPlaneURL,
		RuntimeStateDir:          stateDir,
		RuntimeHeartbeatInterval: time.Second,
	}
}

func startServe(t *testing.T, cfg Config) *serveRun {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	run := &serveRun{socketPath: filepath.Join(shortSocketTempDir(t), "runtime.sock"), cancel: cancel, code: make(chan int, 1)}
	go func() { run.code <- runServeContext(ctx, cfg, run.socketPath, "127.0.0.1:0") }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-run.code:
		case <-time.After(5 * time.Second):
		}
	})
	return run
}

func (r *serveRun) exit(t *testing.T) int {
	t.Helper()
	select {
	case code := <-r.code:
		r.code <- code
		return code
	case <-time.After(5 * time.Second):
		t.Fatal("kei-proxy serve did not exit")
		return -1
	}
}

func (r *serveRun) client() *http.Client {
	return &http.Client{Timeout: time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", r.socketPath)
	}}}
}

// authorizeReason asks the daemon's socket PDP for a decision with the
// runtime token and returns its reason, or "" while the socket has not
// decided. An unauthenticated probe can be refused (401) before the PDP is
// reached, and a refusal must never read as a resolved identity.
func (r *serveRun) authorizeReason() string {
	req, err := http.NewRequest(http.MethodPost, "http://localhost/v1/authorize",
		strings.NewReader(`{"schema":"kei.authorize-request/v1","tool":"web_search","resource":"query"}`))
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+heartbeatTestToken)
	resp, err := r.client().Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var decision struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&decision) != nil || decision.Decision == "" {
		return ""
	}
	return decision.Reason
}

func (r *serveRun) identityResolved() bool {
	reason := r.authorizeReason()
	return reason != "" && reason != "runtime identity is not resolved yet"
}

func TestServeSendsHeartbeats(t *testing.T) {
	cp, server := newFakeControlPlane(t)
	startServe(t, supervisedServeConfig(server.URL, t.TempDir()))
	eventually(t, "two heartbeats from serve", func() bool {
		_, _, beats := cp.counts()
		return beats >= 2
	})
	cp.mu.Lock()
	first := cp.heartbeatBodies[0]
	cp.mu.Unlock()
	if first["runtime_version"] != version || first["schema_version"] != float64(2) || first["run_id"] == "" {
		t.Fatalf("serve heartbeat body = %v, want the v2 body", first)
	}
}

func TestServeResolvesIdentityOnStartup(t *testing.T) {
	cp, server := newFakeControlPlane(t)
	run := startServe(t, supervisedServeConfig(server.URL, t.TempDir()))
	eventually(t, "the socket PDP to have a runtime identity", run.identityResolved)
	if _, whoamis, _ := cp.counts(); whoamis == 0 {
		t.Fatal("serve resolved an identity without calling whoami")
	}
}

func TestServeContextCancelStopsAllChildren(t *testing.T) {
	cp, server := newFakeControlPlane(t)
	stateDir := t.TempDir()
	run := startServe(t, supervisedServeConfig(server.URL, stateDir))
	eventually(t, "identity and a heartbeat", func() bool {
		_, _, beats := cp.counts()
		return beats > 0 && run.identityResolved()
	})
	run.cancel()
	if code := run.exit(t); code != 0 {
		t.Fatalf("serve exit after cancel = %d, want 0", code)
	}
	if _, err := os.Stat(run.socketPath); !os.IsNotExist(err) {
		t.Fatalf("socket after shutdown: stat err = %v, want not-exist", err)
	}
	release, err := keiruntime.ClaimStateDir(stateDir)
	if err != nil {
		t.Fatalf("state directory still owned after serve stopped: %v", err)
	}
	release()
	before, _, _ := cp.counts()
	time.Sleep(1500 * time.Millisecond) // longer than one heartbeat interval
	if after, _, _ := cp.counts(); after != before {
		t.Fatalf("control plane saw %d requests after serve stopped", after-before)
	}
}

func TestServeExitsNonZeroWhenHeartbeatIsRevoked(t *testing.T) {
	cp, server := newFakeControlPlane(t)
	cp.setHeartbeatStatus(http.StatusUnauthorized)
	run := startServe(t, supervisedServeConfig(server.URL, t.TempDir()))
	if code := run.exit(t); code != 1 {
		t.Fatalf("serve exit after a revoked heartbeat = %d, want 1", code)
	}
	if _, err := os.Stat(run.socketPath); !os.IsNotExist(err) {
		t.Fatalf("socket after fatal child: stat err = %v, want every child stopped", err)
	}
}

// A heartbeat started beside serve must exit before it reaches the control
// plane: no second heartbeat, refresher, or collector for serve's state dir.
func TestRuntimeHeartbeatRefusesWhenServeOwnsStateDir(t *testing.T) {
	_, serveCP := newFakeControlPlane(t)
	stateDir := t.TempDir()
	run := startServe(t, supervisedServeConfig(serveCP.URL, stateDir))
	eventually(t, "serve to resolve its identity", run.identityResolved)

	heartbeatCP, heartbeatServer := newFakeControlPlane(t)
	cfg := supervisedServeConfig(heartbeatServer.URL, stateDir)
	cfg.AuditPath = filepath.Join(t.TempDir(), "audit.jsonl")
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"text", nil, heartbeatExitTransient},
		{"jsonl", []string{"--output", "jsonl"}, heartbeatExitConfig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append([]string{"--interval", "1s", "--timeout", "1s"}, tc.args...)
			code := runRuntimeHeartbeat(context.Background(), args, nil, &stdout, &stderr, cfg, envMap(nil), NewRuntimeClient)
			if code != tc.want {
				t.Fatalf("exit = %d, want %d; stderr=%s", code, tc.want, stderr.String())
			}
			if !strings.Contains(stderr.String(), "run only kei-proxy serve") {
				t.Fatalf("stderr = %q, want the serve-owns-the-state-dir message", stderr.String())
			}
		})
	}
	if requests, _, _ := heartbeatCP.counts(); requests != 0 {
		t.Fatalf("refused heartbeat sent %d control-plane requests, want none", requests)
	}
	if _, err := os.Stat(cfg.AuditPath); !os.IsNotExist(err) {
		t.Fatalf("refused heartbeat touched the audit spool: %v", err)
	}
	if !run.identityResolved() {
		t.Fatal("serve lost its identity after a refused heartbeat")
	}
}

// The order that used to break (HAI-438): `runtime heartbeat` and `serve`
// start together on one state directory. Exactly one of them may own it. If
// serve wins it must resolve its identity; if the heartbeat wins, serve must
// fail loudly instead of serving without one.
func TestServeAndHeartbeatStartedTogetherNeverShareStateDir(t *testing.T) {
	for i := range 5 {
		cp, server := newFakeControlPlane(t)
		stateDir := t.TempDir()
		cfg := supervisedServeConfig(server.URL, stateDir)

		heartbeatCtx, stopHeartbeat := context.WithCancel(context.Background())
		var heartbeatErr syncBuffer
		heartbeatCode := make(chan int, 1)
		start := make(chan struct{})
		go func() {
			<-start
			heartbeatCode <- runRuntimeHeartbeat(heartbeatCtx, []string{"--interval", "1s", "--timeout", "1s"}, nil, io.Discard, &heartbeatErr, cfg, envMap(nil), NewRuntimeClient)
		}()
		run := startServe(t, cfg)
		close(start)

		select {
		case code := <-run.code:
			run.code <- code
			// The heartbeat won the state directory; serve must refuse it.
			if code != 1 {
				t.Fatalf("iteration %d: serve exit = %d, want 1 when the heartbeat owns the state dir", i, code)
			}
		case code := <-heartbeatCode:
			heartbeatCode <- code
			// serve won; the heartbeat refused before reaching the catalog.
			if code != heartbeatExitTransient || !strings.Contains(heartbeatErr.String(), "run only kei-proxy serve") {
				t.Fatalf("iteration %d: heartbeat exit = %d, stderr=%q", i, code, heartbeatErr.String())
			}
			eventually(t, "serve to resolve its identity", run.identityResolved)
			eventually(t, "serve's own heartbeat", func() bool {
				_, _, beats := cp.counts()
				return beats > 0
			})
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d: serve and heartbeat both kept running on one state dir", i)
		}
		stopHeartbeat()
		run.cancel()
		run.exit(t)
		select {
		case <-heartbeatCode:
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d: heartbeat did not stop", i)
		}
	}
}

func TestClaimStateDirIsExclusive(t *testing.T) {
	dir := t.TempDir()
	release, err := keiruntime.ClaimStateDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keiruntime.ClaimStateDir(dir); !errors.Is(err, keiruntime.ErrStateDirOwned) {
		t.Fatalf("second claim err = %v, want ErrStateDirOwned", err)
	}
	release()
	release, err = keiruntime.ClaimStateDir(dir)
	if err != nil {
		t.Fatalf("claim after release: %v", err)
	}
	release()
}

// A heartbeat that already owns the state directory makes serve fail loudly
// rather than serve with no refresher and so no identity.
func TestServeRefusesStateDirOwnedByHeartbeat(t *testing.T) {
	cp, server := newFakeControlPlane(t)
	cfg := supervisedServeConfig(server.URL, t.TempDir())
	heartbeat := startHeartbeatWithConfig(t, cfg)
	eventually(t, "the heartbeat to report", func() bool {
		_, _, beats := cp.counts()
		return beats > 0
	})
	run := startServe(t, cfg)
	if code := run.exit(t); code != 1 {
		t.Fatalf("serve exit = %d, want 1 while a heartbeat owns its state dir", code)
	}
	heartbeat.cancel()
	if code := heartbeat.exit(t); code != heartbeatExitOK {
		t.Fatalf("heartbeat exit = %d, want 0; stderr=%s", code, heartbeat.stderr.String())
	}
}

func startHeartbeatWithConfig(t *testing.T, cfg Config) *heartbeatRun {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	run := &heartbeatRun{code: make(chan int, 1), cancel: cancel}
	t.Cleanup(cancel)
	go func() {
		run.code <- runRuntimeHeartbeat(ctx, []string{"--interval", "1s", "--timeout", "1s"}, nil, &run.stdout, &run.stderr, cfg, envMap(nil), NewRuntimeClient)
	}()
	return run
}
