// Package session resolves the authenticated subject for a Kei runtime session.
// The subject lives only in the runtime's per-session memory, set through
// authenticated session routes (HAI-338). It is obtained either from an in-memory
// Sessions struct (for the serve daemon) or by calling GET /v1/session on the
// serve daemon's Unix socket (for one-shot commands like connector invoke and
// authorize).
package session

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"time"
)

// SubjectSource resolves the authenticated subject for the current runtime session.
type SubjectSource interface {
	Subject(context.Context) (string, error)
}

// SubjectTokenSource resolves the subject authentication token for the current
// runtime session. It is optionally implemented alongside SubjectSource.
type SubjectTokenSource interface {
	SubjectToken(context.Context) (string, error)
}

// socketSubjectSource resolves the authenticated subject by calling
// GET /v1/session on the kei-proxy serve daemon's Unix socket.
type socketSubjectSource struct {
	client       *http.Client
	runtimeToken string
}

// NewSocketSubjectSource creates a SubjectSource that dials the serve daemon
// over the given Unix socket path, authenticating with the runtime token.
func NewSocketSubjectSource(socketPath, runtimeToken string) SubjectSource {
	return &socketSubjectSource{
		runtimeToken: runtimeToken,
		client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.DialTimeout("unix", socketPath, 3*time.Second)
				},
			},
		},
	}
}

// Subject calls GET /v1/session on the serve daemon Unix socket and returns
// the user_id of the current session subject. Returns empty string if there
// is no active session (404) or the session subject is not linked.
func (s *socketSubjectSource) Subject(ctx context.Context) (string, error) {
	session, err := s.getSession(ctx)
	if err != nil || session == nil || session.Status != "linked" {
		return "", nil
	}
	return session.UserID, nil
}

// SubjectToken calls GET /v1/session on the serve daemon Unix socket and
// returns the authentication token of the current session subject. Returns
// empty string if there is no active session.
func (s *socketSubjectSource) SubjectToken(ctx context.Context) (string, error) {
	session, err := s.getSession(ctx)
	if err != nil || session == nil {
		return "", nil
	}
	return session.Token, nil
}

type socketSession struct {
	UserID string `json:"user_id"`
	Status string `json:"status"`
	Token  string `json:"token"`
}

func (s *socketSubjectSource) getSession(ctx context.Context) (*socketSession, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/v1/session", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.runtimeToken)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, nil // daemon unreachable → empty
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // no active session → empty
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil // unexpected status → empty (fail closed)
	}

	var session socketSession
	if err := json.NewDecoder(resp.Body).Decode(&session); err != nil {
		return nil, nil // malformed response → empty
	}
	return &session, nil
}
