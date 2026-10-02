package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

// TestServeDaemonOverUnixSocket runs the released binary as a daemon on a
// temporary Unix socket, makes real HTTP requests through the socket, and
// checks that SIGTERM removes the socket while the bounded final flush keeps
// audit data it could not deliver.
func TestServeDaemonOverUnixSocket(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the kei-proxy binary")
	}
	binary := filepath.Join(t.TempDir(), "kei-proxy")
	if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	// macOS limits socket paths to 104 bytes, which t.TempDir can exceed.
	socketDir, err := os.MkdirTemp("/tmp", "h201-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socketPath := filepath.Join(socketDir, "runtime.sock")

	auditDir := t.TempDir()
	auditPath := filepath.Join(auditDir, "audit.jsonl")
	line, err := json.Marshal(keiruntime.DecisionEvent{
		SpanID: "hai201-daemon-retained", InvokingSubject: "user-1", AgentID: "agent-1",
		Framework: "claude", ToolName: "web_search", Decision: "allow",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(auditPath, append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	cmd := exec.Command(binary, "serve")
	cmd.Env = append(os.Environ(),
		"KEI_RUNTIME_TOKEN=kh_live_12345678901234567890",
		// Nothing listens on port 1, so every flush fails fast.
		"KEI_RUNTIME_CONTROL_PLANE_URL=http://127.0.0.1:1",
		"KEI_RUNTIME_SOCKET_PATH="+socketPath,
		"KEI_PROXY_LISTEN_ADDR=127.0.0.1:0",
		"KEI_PROXY_AUDIT="+auditPath,
	)
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		select {
		case <-exited:
		default:
			_ = cmd.Process.Kill()
			<-exited
		}
		if t.Failed() {
			t.Logf("kei-proxy stderr:\n%s", stderr.String())
		}
	})

	var info os.FileInfo
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if info, err = os.Stat(socketPath); err == nil {
			break
		}
	}
	if info == nil {
		t.Fatalf("daemon did not create %s", socketPath)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %v, want 0600 socket", info.Mode())
	}

	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	for path, want := range map[string]int{"/readyz": http.StatusOK, "/v1/models": http.StatusUnauthorized} {
		resp, err := client.Get("http://localhost" + path)
		if err != nil {
			t.Fatalf("GET %s over Unix socket: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("GET %s status = %d, want %d", path, resp.StatusCode, want)
		}
	}
	transport.CloseIdleConnections()

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-exited:
		exited <- err // let the cleanup observe the exit
		if err != nil {
			t.Fatalf("daemon exit after SIGTERM: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("daemon did not exit within the shutdown budget")
	}
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("socket after SIGTERM: stat err = %v, want not-exist", err)
	}

	var retained bool
	_ = filepath.WalkDir(auditDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, readErr := os.ReadFile(path)
		if readErr == nil && strings.Contains(string(data), "hai201-daemon-retained") {
			retained = true
		}
		return nil
	})
	if !retained {
		t.Fatal("undelivered audit record was not retained after the failed shutdown flush")
	}
}
