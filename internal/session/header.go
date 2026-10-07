package session

import (
	"context"
	"net/http"
	"os"
	"strings"
)

// Header names the session a socket request runs in (kei.session/v2): the id
// PUT /v1/session returned. Without it a request uses the legacy default
// session (deprecated).
const Header = "X-Kei-Session"

// EnvID is the environment variable the CLI and harness hooks read the
// session id from when --session is not given.
const EnvID = "KEI_SESSION_ID"

// IDFromEnv returns $KEI_SESSION_ID, trimmed.
func IDFromEnv() string { return strings.TrimSpace(os.Getenv(EnvID)) }

// SetHeader names session id on req; an empty id leaves req unchanged (the
// legacy default session).
func SetHeader(req *http.Request, id string) {
	if id != "" {
		req.Header.Set(Header, id)
	}
}

// FromRequest returns the session id req names, or "" for the default
// session.
func FromRequest(r *http.Request) string { return strings.TrimSpace(r.Header.Get(Header)) }

type ctxKey struct{}

// WithID returns ctx carrying session id, for the subject lookup.
func WithID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// IDFrom returns the session id ctx carries, or $KEI_SESSION_ID when it
// carries none.
func IDFrom(ctx context.Context) string {
	if id, ok := ctx.Value(ctxKey{}).(string); ok {
		return id
	}
	return IDFromEnv()
}
