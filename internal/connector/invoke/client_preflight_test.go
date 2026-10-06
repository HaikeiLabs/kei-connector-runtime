package invoke

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDaemonClientCarriesPreflightHandleToInvokePEP(t *testing.T) {
	socketDir, err := os.MkdirTemp("/tmp", "kp-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(socketDir)
	socketPath := filepath.Join(socketDir, "runtime.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	preflightCalls, invokeCalls := 0, 0
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer runtime-test-token" {
			t.Errorf("authorization header missing")
		}
		switch r.URL.Path {
		case "/v1/preflight":
			preflightCalls++
			var req struct {
				Schema    string         `json:"schema"`
				Tool      string         `json:"tool"`
				Arguments map[string]any `json:"arguments"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
			}
			if req.Schema != "kei.preflight-request/v1" || req.Tool != "github.review_pr" || req.Arguments["id"] != "42" {
				t.Errorf("preflight request=%+v", req)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"schema":"kei.preflight-response/v1","handle":"opaque-preflight-handle"}`)
		case DaemonInvokePath:
			invokeCalls++
			var req daemonRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
			}
			if req.ToolName != "github.review_pr" || req.PreflightHandle != "opaque-preflight-handle" || req.ConnectorID != "" || req.Capability != "" {
				t.Errorf("invoke request not bound to preflight: %+v", req)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"schema":"kei.connector-invoke-response/v1","decision":"allow","result":{"ok":true}}`)
		default:
			http.NotFound(w, r)
		}
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	var stdout, stderr strings.Builder
	code := Run([]string{"--tool", "github.review_pr", "--agent-id", execAgent, "--input", `{"id":"42"}`}, Env{RuntimeToken: "runtime-test-token", DaemonSocket: socketPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if preflightCalls != 1 || invokeCalls != 1 {
		t.Fatalf("preflight calls=%d invoke calls=%d", preflightCalls, invokeCalls)
	}
	if _, err := os.Stat(socketPath); err != nil {
		t.Fatal(err)
	}
}
