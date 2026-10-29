package connectorruntime

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// daemonStub serves POST /v1/authorize on a Unix socket and records the last
// request's session header and body.
func daemonStub(t *testing.T, reply string) (socketPath string, got *struct {
	session, auth string
	body          map[string]any
}) {
	t.Helper()
	dir, err := os.MkdirTemp("", "kei")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socketPath = filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	got = &struct {
		session, auth string
		body          map[string]any
	}{}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.session, got.auth = r.Header.Get("X-Kei-Session"), r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&got.body)
		_, _ = w.Write([]byte(reply))
	})}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return socketPath, got
}

func TestAuthorizeViaDaemonMapsDecisionAndSendsSession(t *testing.T) {
	for _, tc := range []struct {
		reply, decision string
	}{
		{`{"schema":"kei.authorize-response/v1","decision":"permit","bundle_state":"ready"}`, "allow"},
		{`{"schema":"kei.authorize-response/v1","decision":"deny","reason_code":"no_matching_policy","deny_source":"policy","bundle_state":"ready"}`, "deny"},
		{`{"schema":"kei.authorize-response/v1","decision":"unmatched","reason_code":"no_matching_policy","bundle_state":"ready"}`, "deny"},
	} {
		path, got := daemonStub(t, tc.reply)
		out, err := authorizeViaDaemon(context.Background(), path, "tok", "ks_1", daemonAuthorizeCall{Tool: "web_search", Action: "tool:web_search", AgentID: "agent-1"})
		if err != nil || out.Decision != tc.decision {
			t.Fatalf("reply %s: out=%+v err=%v", tc.reply, out, err)
		}
		if got.session != "ks_1" || got.auth != "Bearer tok" || got.body["tool"] != "web_search" || got.body["schema"] != "kei.authorize-request/v1" {
			t.Fatalf("request = %+v", got)
		}
	}
}

func TestAuthorizeViaDaemonErrorsWhenNoDaemonRuns(t *testing.T) {
	if _, err := authorizeViaDaemon(context.Background(), filepath.Join(t.TempDir(), "none.sock"), "tok", "ks_1", daemonAuthorizeCall{Tool: "web_search"}); err == nil {
		t.Fatal("want an error when no daemon is listening")
	}
}
