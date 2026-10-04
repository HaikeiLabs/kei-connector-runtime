package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type OrgRole struct {
	ID          string   `json:"id"`
	OrgID       string   `json:"org_id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	IsDefault   bool     `json:"is_default"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

type RolesResponse struct {
	Roles []OrgRole `json:"roles"`
}

type ABACRolesClient interface {
	ListRoles(ctx context.Context, orgID string) (*RolesResponse, error)
}

type abacRolesClient struct {
	baseURL string
	client  *http.Client
}

func NewABACRolesClient(baseURL string, timeout time.Duration) ABACRolesClient {
	return &abacRolesClient{
		baseURL: baseURL,
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *abacRolesClient) ListRoles(ctx context.Context, orgID string) (*RolesResponse, error) {
	url := fmt.Sprintf("%s/api/v1/orgs/%s/roles", c.baseURL, orgID)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build roles request: %w", err)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("roles request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("roles returned status %d: %s", resp.StatusCode, string(body))
	}

	var rolesResp RolesResponse
	if err := json.NewDecoder(resp.Body).Decode(&rolesResp); err != nil {
		return nil, fmt.Errorf("decode roles response: %w", err)
	}

	return &rolesResp, nil
}
