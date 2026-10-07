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
// the user_id of the session ctx names (WithID, else $KEI_SESSION_ID, else the
// legacy default session). Returns empty string if there is no such session
// (404) or its subject is not linked.
func (s *socketSubjectSource) Subject(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/v1/session", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+s.runtimeToken)
	SetHeader(req, IDFrom(ctx))

	resp, err := s.client.Do(req)
	if err != nil {
		return "", nil // daemon unreachable → empty subject
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", nil // no active session → empty subject
	}
	if resp.StatusCode != http.StatusOK {
		return "", nil // unexpected status → empty subject (fail closed)
	}

	var session struct {
		UserID string `json:"user_id"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&session); err != nil {
		return "", nil // malformed response → empty subject
	}
	if session.Status != "linked" {
		return "", nil
	}
	return session.UserID, nil
}
