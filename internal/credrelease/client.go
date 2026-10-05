// Package credrelease fetches a session subject's connector credentials from
// the identity service (ADR-032 §5 I11) and holds them in the kei-proxy serve
// daemon's memory for the session (ADR-034, owner option A). Credential values
// never leave this package except as the argument of a Store.Use callback, and
// no error, log line or String form carries one.
package credrelease

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ResolvePath is the identity service's I11 credential release method.
const ResolvePath = "/api/v1/connectorCredentials:resolve"

// maxResolveResponse bounds the I11 response body read into memory.
const maxResolveResponse = 1 << 20

var (
	// ErrUnauthenticated is I11 401: the runtime or subject token was rejected.
	ErrUnauthenticated = errors.New("credrelease: identity service rejected the runtime or subject token")
	// ErrSubjectUnlinked is I11 403: the subject's remote identity is not linked.
	ErrSubjectUnlinked = errors.New("credrelease: subject is not linked")
	// ErrUnavailable is any other I11 failure (transport, 4xx, 5xx, bad body).
	ErrUnavailable = errors.New("credrelease: identity service unavailable")
)

// Failure reasons returned by I11 for one provider.
const (
	ReasonNotConnected        = "NOT_CONNECTED"
	ReasonReconnectRequired   = "RECONNECT_REQUIRED"
	ReasonMaxLifetimeExceeded = "MAX_LIFETIME_EXCEEDED"
	ReasonProviderUnavailable = "PROVIDER_UNAVAILABLE"
)

// Client calls I11 with the runtime token and a subject token.
type Client struct {
	baseURL      string
	runtimeToken string
	httpClient   *http.Client
}

// NewClient returns an I11 client for the identity service (or gateway) at
// baseURL, authenticating with the runtime installation token.
func NewClient(baseURL, runtimeToken string, timeout time.Duration) *Client {
	return &Client{
		baseURL:      strings.TrimRight(baseURL, "/"),
		runtimeToken: runtimeToken,
		httpClient:   &http.Client{Timeout: timeout},
	}
}

// resolveRequest is the I11 body. Empty providers means every connection the
// subject made in the workspace.
type resolveRequest struct {
	Providers []string `json:"providers,omitempty"`
}

type resolveResponse struct {
	Credentials []struct {
		Provider    string `json:"provider"`
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	} `json:"credentials"`
	Failures []struct {
		Provider string `json:"provider"`
		Reason   string `json:"reason"`
	} `json:"failures"`
}

// resolved is one I11 result: provider → token bytes, and provider → failure
// reason. The token bytes are owned by the caller, which must zero them.
type resolved struct {
	tokens   map[string][]byte
	failures map[string]string
}

// resolve calls I11 once. providers nil fetches every connection.
func (c *Client) resolve(ctx context.Context, subjectToken string, providers []string) (resolved, error) {
	body, err := json.Marshal(resolveRequest{Providers: providers})
	if err != nil {
		return resolved{}, ErrUnavailable
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+ResolvePath, bytes.NewReader(body))
	if err != nil {
		return resolved{}, ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+c.runtimeToken)
	req.Header.Set("X-Kei-Subject-Token", subjectToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return resolved{}, fmt.Errorf("%w: request failed", ErrUnavailable)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return resolved{}, ErrUnauthenticated
	case http.StatusForbidden:
		return resolved{}, ErrSubjectUnlinked
	default:
		return resolved{}, fmt.Errorf("%w: status %d", ErrUnavailable, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResolveResponse))
	if err != nil {
		return resolved{}, ErrUnavailable
	}
	defer zero(raw)
	var decoded resolveResponse
	if err := json.Unmarshal(raw, &decoded); err != nil {
		// The decode error may quote the body, so it is dropped.
		return resolved{}, fmt.Errorf("%w: malformed response", ErrUnavailable)
	}
	out := resolved{tokens: map[string][]byte{}, failures: map[string]string{}}
	for _, f := range decoded.Failures {
		if f.Provider != "" {
			out.failures[f.Provider] = f.Reason
		}
	}
	for _, cr := range decoded.Credentials {
		if cr.Provider == "" || cr.AccessToken == "" {
			continue
		}
		if cr.TokenType != "" && !strings.EqualFold(cr.TokenType, "bearer") {
			continue
		}
		out.tokens[cr.Provider] = []byte(cr.AccessToken)
		delete(out.failures, cr.Provider)
	}
	return out, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
