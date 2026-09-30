package connectorruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type AuthorizeRequest struct {
	HarnessToken   string `json:"harness_token,omitempty"`
	UserID         string `json:"user_id,omitempty"`
	ProviderUserID string `json:"provider_user_id,omitempty"`
	Action         string `json:"action"`
	// Tool names the tool being invoked (HAI-271). When set, the catalog
	// decides against the workspace tool registry scope instead of the
	// caller's resource.
	Tool        string `json:"tool,omitempty"`
	Resource    string `json:"resource,omitempty"`
	Service     string `json:"service,omitempty"`
	AgentID     string `json:"agent_id,omitempty"`
	WorkspaceID string `json:"workspace_id,omitempty"`

	InvokingSubject string   `json:"invoking_subject,omitempty"`
	ParentSpan      string   `json:"parent_span,omitempty"`
	DelegationDepth int      `json:"delegation_depth,omitempty"`
	AgentVersion    string   `json:"agent_version,omitempty"`
	Framework       string   `json:"framework,omitempty"`
	ToolArgsDigest  string   `json:"tool_args_digest,omitempty"`
	Resources       []string `json:"resources,omitempty"`
}

type AuthorizeResponse struct {
	Decision    string           `json:"decision"`
	Reason      string           `json:"reason,omitempty"`
	OrgID       *string          `json:"org_id,omitempty"`
	UserID      *string          `json:"user_id,omitempty"`
	PolicyID    string           `json:"policy_id,omitempty"`
	WorkspaceID *string          `json:"workspace_id,omitempty"`
	Enrollment  *json.RawMessage `json:"enrollment,omitempty"`
	Connect     *json.RawMessage `json:"connect,omitempty"`
}

type ABACClient interface {
	Authorize(ctx context.Context, req AuthorizeRequest) (*AuthorizeResponse, error)
}

type abacClient struct {
	baseURL string
	secret  string
	client  *http.Client
}

func NewABACClient(baseURL, secret string, timeout time.Duration) ABACClient {
	return &abacClient{
		baseURL: baseURL,
		secret:  secret,
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *abacClient) Authorize(ctx context.Context, req AuthorizeRequest) (*AuthorizeResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal authorize request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/authorize", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build authorize request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// Service-to-service authentication to the ABAC engine. The application
	// credential travels in X-KEI-API-Key; Authorization is reserved for the
	// platform transport layer (ADR-009). Callers that fail to configure this
	// in production are rejected before reaching here.
	if c.secret != "" {
		httpReq.Header.Set("X-KEI-API-Key", c.secret)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("authorize request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read authorize response: %w", err)
	}

	// A rejected proxy identity must fail closed, never degrade to a decision.
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("ABAC rejected proxy credentials (status %d)", resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authorize returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var authResp AuthorizeResponse
	if err := json.Unmarshal(respBody, &authResp); err != nil {
		return nil, fmt.Errorf("unmarshal authorize response: %w", err)
	}

	return &authResp, nil
}
