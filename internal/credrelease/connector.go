package credrelease

// Connector-scoped credential release (HAI-577, kei-oidc-bridge #69): the
// token of one connector's connection for one resource, which the /mcp route
// attaches upstream (ADR-036 §4.8). It uses the I11 caller authentication:
// the runtime token and the session's subject token.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

// connectorResolvePath is the bridge's per-connector release method.
func connectorResolvePath(connectorID string) string {
	return "/api/v1/connectorCredentials/" + url.PathEscape(connectorID) + ":resolve"
}

// ConnectorCredential is one connector's released token with the audience
// the bridge recorded for it. AccessToken reaches code only inside a
// UseConnector callback.
type ConnectorCredential struct {
	ConnectorID, Issuer, Resource, AccountModel, AccessToken string
}

type heldConnectorToken struct {
	token                                       []byte
	connectorID, issuer, resource, accountModel string
}

type connectorResolveResponse struct {
	ConnectorID  string `json:"connector_id"`
	Issuer       string `json:"issuer"`
	Resource     string `json:"resource"`
	AccountModel string `json:"account_model"`
	Credential   *struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	} `json:"credential"`
	Failure *struct {
		Reason string `json:"reason"`
	} `json:"failure"`
}

// resolveConnector makes one per-connector release call.
func (c *Client) resolveConnector(ctx context.Context, subjectToken, connectorID, resource string) (heldConnectorToken, error) {
	body, err := json.Marshal(struct {
		Resource string `json:"resource"`
	}{resource})
	if err != nil {
		return heldConnectorToken{}, ErrUnavailable
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+connectorResolvePath(connectorID), bytes.NewReader(body))
	if err != nil {
		return heldConnectorToken{}, ErrUnavailable
	}
	requestID := uuid.NewString()
	req.Header.Set("Authorization", "Bearer "+c.runtimeToken)
	req.Header.Set("X-Kei-Subject-Token", subjectToken)
	req.Header.Set("X-Request-ID", requestID)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return heldConnectorToken{}, requestError(fmt.Errorf("%w: request failed", ErrUnavailable), req, requestID, nil)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return heldConnectorToken{}, requestError(ErrUnauthenticated, req, requestID, resp)
	case http.StatusForbidden:
		return heldConnectorToken{}, requestError(ErrSubjectUnlinked, req, requestID, resp)
	default:
		return heldConnectorToken{}, requestError(fmt.Errorf("%w: status %d", ErrUnavailable, resp.StatusCode), req, requestID, resp)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResolveResponse))
	if err != nil {
		return heldConnectorToken{}, requestError(ErrUnavailable, req, requestID, resp)
	}
	defer zero(raw)
	var decoded connectorResolveResponse
	if err := json.Unmarshal(raw, &decoded); err != nil {
		// The decode error may quote the body, so it is dropped.
		return heldConnectorToken{}, requestError(fmt.Errorf("%w: malformed response", ErrUnavailable), req, requestID, resp)
	}
	held := heldConnectorToken{connectorID: decoded.ConnectorID, issuer: decoded.Issuer, resource: decoded.Resource, accountModel: decoded.AccountModel}
	switch {
	case decoded.Failure != nil && decoded.Failure.Reason != "":
		return held, &DeniedError{Provider: connectorID, Reason: decoded.Failure.Reason}
	case decoded.Credential == nil || decoded.Credential.AccessToken == "":
		return held, &DeniedError{Provider: connectorID, Reason: ReasonNotConnected}
	case decoded.Credential.TokenType != "" && !strings.EqualFold(decoded.Credential.TokenType, "bearer"):
		return held, &DeniedError{Provider: connectorID, Reason: ReasonNotConnected}
	}
	held.token = []byte(decoded.Credential.AccessToken)
	return held, nil
}

func connectorKey(connectorID, resource string) string { return connectorID + "|" + resource }

// UseConnector runs fn with the session's credential for connectorID and
// resource, if the held session belongs to subject. The first use resolves
// it through the bridge; later uses reuse it until DropConnector or Flush.
// A failure (a *DeniedError with the bridge's reason, such as
// AUDIENCE_MISMATCH or NOT_CONNECTED) is not cached. The credential is a
// copy and fn must not retain it.
func (s *Store) UseConnector(ctx context.Context, subject, connectorID, resource string, fn func(ConnectorCredential) error) error {
	key := connectorKey(connectorID, resource)
	s.mu.Lock()
	if subject == "" || s.subject != subject || s.subjectToken == "" {
		s.mu.Unlock()
		return &DeniedError{Provider: connectorID, Reason: ReasonNoSession}
	}
	held, ok := s.connectorTokens[key]
	gen, subjectToken := s.gen, s.subjectToken
	s.mu.Unlock()

	if !ok {
		resolved, err := s.client.resolveConnector(ctx, subjectToken, connectorID, resource)
		if err != nil {
			return err
		}
		s.mu.Lock()
		if s.gen != gen {
			s.mu.Unlock()
			zero(resolved.token)
			return &DeniedError{Provider: connectorID, Reason: ReasonNoSession}
		}
		if s.connectorTokens == nil {
			s.connectorTokens = map[string]heldConnectorToken{}
		}
		s.connectorTokens[key] = resolved
		s.mu.Unlock()
		held = resolved
	}
	return fn(ConnectorCredential{
		ConnectorID: held.connectorID, Issuer: held.issuer, Resource: held.resource,
		AccountModel: held.accountModel, AccessToken: string(held.token),
	})
}

// DropConnector zeroes and forgets the held credential for connectorID and
// resource, after the upstream rejected it (ADR-036 §4.8 credential_rejected).
func (s *Store) DropConnector(connectorID, resource string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := connectorKey(connectorID, resource)
	if held, ok := s.connectorTokens[key]; ok {
		zero(held.token)
		delete(s.connectorTokens, key)
	}
}
