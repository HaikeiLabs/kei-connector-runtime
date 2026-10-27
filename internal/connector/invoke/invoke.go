// Package invoke holds the shared wire types and the catalog client for
// governed connector calls, plus the decision types the serve daemon's
// credentialed connector routes use (the POST /v1/commands:run runner in
// internal/run). The runtime's own connector execution (`connector invoke`
// and POST /v1/connectors:invoke) was removed by HAI-724: the runtime is
// decision-only (ADR-039).
package invoke

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/envelope"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/credentials"
)

// Request is the wire shape a harness sends to ABAC's governed
// connector invocation endpoint. Tenant/workspace/agent are resolved
// server-side from the harness token; the proxy only forwards the capability,
// the resource, and the identity-propagation context.
type Request struct {
	HarnessToken    string `json:"harness_token"`
	ToolName        string `json:"tool_name,omitempty"`
	PreflightHandle string `json:"preflight_handle,omitempty"`
	ParentSpan      string `json:"parent_span,omitempty"`
	DelegationDepth int    `json:"delegation_depth,omitempty"`
	AgentID         string `json:"agent_id,omitempty"`
	ConnectorID     string `json:"connector_id"`
	Capability      string `json:"capability"`
	Action          string `json:"action"`
	Resource        string `json:"resource"`
	TraceID         string `json:"trace_id"`
	IdempotencyKey  string `json:"idempotency_key,omitempty"`
	InvokingSubject string `json:"invoking_subject,omitempty"`
	OnBehalfOf      string `json:"on_behalf_of,omitempty"`
	UserID          string `json:"user_id,omitempty"`
	Framework       string `json:"framework,omitempty"`
	// ProviderUserID is the chat-platform identity (e.g. a WhatsApp E.164
	// number); the catalog resolves it to the invoking Kei user.
	ProviderUserID string `json:"provider_user_id,omitempty"`
	// InputDigest binds the decision to the capability input without sending
	// it: "sha256:<hex>" of the canonical input JSON.
	InputDigest string `json:"input_digest,omitempty"`
}

// Response mirrors the ABAC invoke response. On an allow the envelope
// carries the propagation chain minted by the control plane, the connector
// descriptor, and, for an OAuth connector, the token proxied for this call
// (D2). A deny carries a reason and, where known, a reason code.
type Response struct {
	Decision          string                  `json:"decision"`
	Reason            string                  `json:"reason,omitempty"`
	ReasonCode        string                  `json:"reason_code,omitempty"`
	Envelope          *envelope.Envelope      `json:"envelope,omitempty"`
	Connector         *Descriptor             `json:"connector,omitempty"`
	CredentialSubject string                  `json:"credential_subject,omitempty"`
	OAuth             *credentials.OAuthToken `json:"oauth,omitempty"`
	Enrollment        *json.RawMessage        `json:"enrollment,omitempty"`
	Connect           *json.RawMessage        `json:"connect,omitempty"`
}

// Client calls the control plane's governed connector endpoint.
type Client struct {
	baseURL string
	token   string
	client  *http.Client
}

// NewClient returns a Client for the control-plane baseURL. The request
// authenticates itself with the runtime token it carries.
func NewClient(baseURL string, timeout time.Duration) *Client {
	return &Client{baseURL: baseURL, client: &http.Client{Timeout: timeout}}
}

// WithBearerToken sets the runtime bearer token sent as Authorization: Bearer.
func (c *Client) WithBearerToken(token string) *Client {
	c.token = token
	return c
}

// Invoke calls the governed connector invocation endpoint and fails closed on
// any non-200 status, so a rejected or unavailable control plane never yields
// a decision the harness could act on.
func (c *Client) Invoke(ctx context.Context, req Request) (*Response, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal connector invoke request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/data-connectors/invoke", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build connector invoke request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("connector invoke request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read connector invoke response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("ABAC rejected proxy credentials (status %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("connector invoke returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var out Response
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("unmarshal connector invoke response: %w", err)
	}
	return &out, nil
}
