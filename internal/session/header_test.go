package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSubjectSourceSendsSessionHeader: the subject lookup names the session
// from the context, else $KEI_SESSION_ID, else no header (default session).
func TestSubjectSourceSendsSessionHeader(t *testing.T) {
	socketPath := testSocketPath(t)
	got := make(chan string, 4)
	server := launchSessionSocket(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get(Header)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"user_id":"user-abc","status":"linked"}`))
	}))
	defer server.Close()
	source := NewSocketSubjectSource(socketPath, "test-token")

	t.Setenv(EnvID, "")
	_, _ = source.Subject(context.Background())
	if h := <-got; h != "" {
		t.Errorf("no session: header %q, want none", h)
	}
	t.Setenv(EnvID, " ks_from-env ")
	_, _ = source.Subject(context.Background())
	if h := <-got; h != "ks_from-env" {
		t.Errorf("env session: header %q", h)
	}
	_, _ = source.Subject(WithID(context.Background(), "ks_from-flag"))
	if h := <-got; h != "ks_from-flag" {
		t.Errorf("flag session overrides env: header %q", h)
	}
	_, _ = source.Subject(WithID(context.Background(), ""))
	if h := <-got; h != "" {
		t.Errorf("explicit empty session: header %q, want none", h)
	}
}

func TestSessionHeaderHelpers(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	SetHeader(req, "")
	if FromRequest(req) != "" {
		t.Error("an empty id set a header")
	}
	SetHeader(req, "ks_x")
	if FromRequest(req) != "ks_x" {
		t.Errorf("FromRequest = %q", FromRequest(req))
	}
}
