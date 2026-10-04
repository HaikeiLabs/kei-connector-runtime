package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type RoleRequest struct {
	ID            string `json:"id"`
	OrgID         string `json:"org_id"`
	UserID        string `json:"user_id"`
	RequestedRole string `json:"requested_role"`
	Status        string `json:"status"`
	Harness       string `json:"harness"`
	RequestedBy   string `json:"requested_by,omitempty"`
	Reason        string `json:"reason,omitempty"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

type RoleRequestResponse struct {
	Request RoleRequest `json:"request"`
}

type CreateRoleRequestInput struct {
	UserID        string `json:"user_id"`
	OrgID         string `json:"org_id"`
	RequestedRole string `json:"requested_role"`
	Harness       string `json:"harness"`
	RequestedBy   string `json:"requested_by"`
	Reason        string `json:"reason"`
}

type ABACRoleRequestClient interface {
	CreateRoleRequest(ctx context.Context, input CreateRoleRequestInput) (*RoleRequest, error)
	GetRoleRequest(ctx context.Context, id string) (*RoleRequest, error)
}

type abacRoleRequestClient struct {
	baseURL string
	client  *http.Client
}

func NewABACRoleRequestClient(baseURL string, timeout time.Duration) ABACRoleRequestClient {
	return &abacRoleRequestClient{
		baseURL: baseURL,
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *abacRoleRequestClient) CreateRoleRequest(ctx context.Context, input CreateRoleRequestInput) (*RoleRequest, error) {
	body, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	url := c.baseURL + "/api/v1/role-requests"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("role-request returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var reqResp RoleRequestResponse
	if err := json.NewDecoder(resp.Body).Decode(&reqResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &reqResp.Request, nil
}

func (c *abacRoleRequestClient) GetRoleRequest(ctx context.Context, id string) (*RoleRequest, error) {
	url := fmt.Sprintf("%s/api/v1/role-requests/%s", c.baseURL, id)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("role-request returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var reqResp RoleRequestResponse
	if err := json.NewDecoder(resp.Body).Decode(&reqResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &reqResp.Request, nil
}
