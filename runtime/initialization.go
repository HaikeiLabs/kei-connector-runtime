package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// MemberInitRequest is the canonical member-provisioning request the ABAC
// engine expects at POST /api/v1/initialize.
type MemberInitRequest struct {
	UserID string `json:"user_id"`
	OrgID  string `json:"org_id"`
}

// MemberInitResponse mirrors the ABAC engine's member provisioning response.
type MemberInitResponse struct {
	UserID      string `json:"user_id"`
	OrgID       string `json:"org_id"`
	Role        string `json:"role"`
	GroupID     string `json:"group_id"`
	Initialized bool   `json:"initialized"`
}

// AgentInitRequest is the canonical agent-provisioning request the ABAC engine
// expects at POST /api/v1/agents. OrgID is carried as a query parameter (not a
// body field) to match the ABAC handler. Declared tools and data scopes are the
// tool/resource context forwarded from the harness.
type AgentInitRequest struct {
	OrgID              string          `json:"-"`
	Name               string          `json:"name"`
	Description        string          `json:"description,omitempty"`
	ConnectionID       string          `json:"connection_id,omitempty"`
	ModelProfileID     string          `json:"model_profile_id,omitempty"`
	DeclaredTools      json.RawMessage `json:"declared_tools,omitempty"`
	DeclaredDataScopes json.RawMessage `json:"declared_data_scopes,omitempty"`
}

// AgentInitResponse mirrors the ABAC engine's agent provisioning response.
type AgentInitResponse struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	Initialized bool   `json:"initialized"`
}

// InitializationClient talks to the canonical ABAC initialization endpoints.
// It performs no local provisioning or permission decisions: every outcome is
// taken from the ABAC engine, and any transport or HTTP failure is returned to
// the caller so it can fail closed.
type InitializationClient interface {
	InitializeMember(ctx context.Context, req MemberInitRequest) (*MemberInitResponse, error)
	InitializeAgent(ctx context.Context, req AgentInitRequest) (*AgentInitResponse, error)
}

type initializationClient struct {
	baseURL string
	secret  string
	client  *http.Client
}

func NewInitializationClient(baseURL, secret string, timeout time.Duration) InitializationClient {
	return &initializationClient{
		baseURL: baseURL,
		secret:  secret,
		client:  &http.Client{Timeout: timeout},
	}
}

// setAuth applies the shared request headers. The service-to-service
// credential travels in X-KEI-API-Key (ADR-009); it is omitted when unset so
// development environments without an ABAC secret still work.
func (c *initializationClient) setAuth(r *http.Request) {
	r.Header.Set("Content-Type", "application/json")
	if c.secret != "" {
		r.Header.Set("X-KEI-API-Key", c.secret)
	}
}

// InitializeMember calls the canonical member-provisioning endpoint. There is
// no local fallback: a non-200 status or transport error is returned verbatim.
func (c *initializationClient) InitializeMember(ctx context.Context, req MemberInitRequest) (*MemberInitResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal member init request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/initialize", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build member init request: %w", err)
	}
	c.setAuth(httpReq)

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("member initialization request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read member init response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("member initialization returned status %d: %s", resp.StatusCode, string(respBody))
	}
	var out MemberInitResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("unmarshal member init response: %w", err)
	}
	return &out, nil
}

// InitializeAgent calls the canonical agent-provisioning endpoint. The org is
// carried as a query parameter to match the ABAC handler. There is no local
// fallback: a non-200 status or transport error is returned verbatim.
func (c *initializationClient) InitializeAgent(ctx context.Context, req AgentInitRequest) (*AgentInitResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal agent init request: %w", err)
	}
	q := url.Values{}
	q.Set("org_id", req.OrgID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/agents?"+q.Encode(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build agent init request: %w", err)
	}
	c.setAuth(httpReq)

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("agent initialization request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read agent init response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent initialization returned status %d: %s", resp.StatusCode, string(respBody))
	}
	var out AgentInitResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("unmarshal agent init response: %w", err)
	}
	return &out, nil
}
