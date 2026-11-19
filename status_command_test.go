package connectorruntime

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProbeDaemonStatusAbsent(t *testing.T) {
	result := probeDaemonStatus(filepath.Join(shortSocketTempDir(t), "absent.sock"))
	if result.state != "unavailable" || result.version != "" || result.reason != "socket not found" {
		t.Fatalf("status = %+v", result)
	}
}

func TestProbeDaemonStatusUnready(t *testing.T) {
	path := filepath.Join(shortSocketTempDir(t), "runtime.sock")
	startStatusTestServer(t, path, http.StatusServiceUnavailable, "v2.3.4", "secret-response-canary")

	result := probeDaemonStatus(path)
	if result.state != "running (unready)" || result.version != "v2.3.4" {
		t.Fatalf("status = %+v", result)
	}
	t.Setenv("KEI_RUNTIME_SOCKET_PATH", path)
	var stdout, stderr bytes.Buffer
	if code := runStatusWithWriters(nil, &stdout, &stderr); code == 0 {
		t.Fatal("unready daemon unexpectedly returned success")
	}
	if strings.Contains(stdout.String()+stderr.String(), "secret-response-canary") {
		t.Fatalf("status output leaked readiness response body: %s", stdout.String()+stderr.String())
	}
}

func TestProbeDaemonStatusReadyAndSafeOutput(t *testing.T) {
	dir := shortSocketTempDir(t)
	path := filepath.Join(dir, "private-token-canary", "runtime.sock")
	if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	startStatusTestServer(t, path, http.StatusOK, "v9.8.7", "body-secret-canary")
	t.Setenv("KEI_RUNTIME_SOCKET_PATH", path)

	result := probeDaemonStatus(path)
	if result.state != "ready" || result.version != "v9.8.7" {
		t.Fatalf("status = %+v", result)
	}

	var stdout, stderr bytes.Buffer
	if code := runStatusWithWriters(nil, &stdout, &stderr); code != 0 {
		t.Fatalf("runStatus exit = %d, stderr=%q", code, stderr.String())
	}
	got := stdout.String()
	for _, forbidden := range []string{dir, "private-token-canary", "body-secret-canary", "KEI_RUNTIME_TOKEN"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("status output leaked %q: %s", forbidden, got)
		}
	}
	for _, required := range []string{"status: ready", "socket: custom Unix socket (path redacted)", "version: v9.8.7"} {
		if !strings.Contains(got, required) {
			t.Fatalf("status output missing %q: %s", required, got)
		}
	}
}

func TestProbeDaemonStatusStaleSocket(t *testing.T) {
	path := filepath.Join(shortSocketTempDir(t), "runtime.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	listener.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	result := probeDaemonStatus(path)
	if result.state != "unavailable" || result.reason != "stale socket" {
		t.Fatalf("status = %+v, want unavailable stale socket", result)
	}
}

func TestProbeDaemonStatusRejectsNonOwnerOnlySocket(t *testing.T) {
	path := filepath.Join(shortSocketTempDir(t), "runtime.sock")
	startStatusTestServer(t, path, http.StatusOK, "v1.0.0", "")
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	result := probeDaemonStatus(path)
	if result.state != "unavailable" || result.reason != "socket permissions are not owner-only" {
		t.Fatalf("status = %+v", result)
	}
}

func TestStatusHelpAndVersionDoNotCreateSocket(t *testing.T) {
	path := filepath.Join(shortSocketTempDir(t), "must-not-be-created.sock")
	t.Setenv("KEI_RUNTIME_SOCKET_PATH", path)

	if code := Main("test-version", []string{"--version"}); code != 0 {
		t.Fatalf("--version exit = %d", code)
	}
	if code := Main("test-version", []string{"--help"}); code != 0 {
		t.Fatalf("--help exit = %d", code)
	}
	if code := Main("test-version", []string{"status"}); code == 0 {
		t.Fatal("status for absent daemon unexpectedly succeeded")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("status/help/version created socket or returned unexpected stat error: %v", err)
	}
}

func startStatusTestServer(t *testing.T, path string, status int, buildVersion, body string) {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/readyz" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("X-Kei-Proxy-Version", buildVersion)
		w.WriteHeader(status)
		_, _ = fmt.Fprintln(w, body)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
}
