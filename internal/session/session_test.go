package session

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestSocketSubjectSourceReturnsUserIDWhenLinked(t *testing.T) {
	socketPath := testSocketPath(t)
	server := launchSessionSocket(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/v1/session" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"user_id":"user-abc","status":"linked"}`))
	}))
	defer server.Close()

	source := NewSocketSubjectSource(socketPath, "test-token")
	userID, err := source.Subject(context.Background())
	if err != nil || userID != "user-abc" {
		t.Fatalf("Subject() = %q, %v", userID, err)
	}
}

func TestSocketSubjectSourceReturnsEmptyOn404(t *testing.T) {
	socketPath := testSocketPath(t)
	server := launchSessionSocket(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	source := NewSocketSubjectSource(socketPath, "test-token")
	userID, err := source.Subject(context.Background())
	if err != nil || userID != "" {
		t.Fatalf("Subject() = %q, %v", userID, err)
	}
}

func TestSocketSubjectSourceReturnsEmptyOnUnlinkedStatus(t *testing.T) {
	socketPath := testSocketPath(t)
	server := launchSessionSocket(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"user_id":"user-abc","status":"pending"}`))
	}))
	defer server.Close()

	source := NewSocketSubjectSource(socketPath, "test-token")
	userID, err := source.Subject(context.Background())
	if err != nil || userID != "" {
		t.Fatalf("Subject() = %q, %v", userID, err)
	}
}

func TestSocketSubjectSourceReturnsEmptyOnDaemonUnreachable(t *testing.T) {
	source := NewSocketSubjectSource("/nonexistent/socket", "test-token")
	userID, err := source.Subject(context.Background())
	if err != nil || userID != "" {
		t.Fatalf("Subject() = %q, %v", userID, err)
	}
}

// testSocketPath returns a short Unix socket path for testing.
func testSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(os.TempDir(), "s-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

// launchSessionSocket starts an HTTP server on a Unix socket at the given path.
// The caller must close the returned server.
func launchSessionSocket(t *testing.T, socketPath string, handler http.Handler) *http.Server {
	t.Helper()
	server := &http.Server{Handler: handler}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen %s: %v", socketPath, err)
	}
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Close()
		os.Remove(socketPath)
	})
	return server
}
