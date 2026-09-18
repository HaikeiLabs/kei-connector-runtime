package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
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

type rolesParams struct {
	ctx     context.Context
	org     string
	harness string
	abac    ABACRolesClient
	timeout time.Duration
}

func listRoles(p rolesParams) ([]OrgRole, error) {
	if p.org == "" {
		return nil, fmt.Errorf("org is required")
	}

	resp, err := p.abac.ListRoles(p.ctx, p.org)
	if err != nil {
		return nil, err
	}

	return resp.Roles, nil
}

func runRoles(args []string) int {
	fs := flag.NewFlagSet("roles", flag.ContinueOnError)
	org := fs.String("org", "", "organization ID")
	abacURL := fs.String("abac-url", "", "ABAC Engine URL (default $ABAC_URL)")
	timeout := fs.Int("timeout", 30, "request timeout in seconds")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	cfg := configFromEnv()
	if *abacURL != "" {
		cfg.ABACURL = *abacURL
	}

	if cfg.HarnessToken == "" {
		fmt.Fprintln(os.Stderr, "Error: KEI_HARNESS_TOKEN is not set")
		return 1
	}

	client := NewABACRolesClient(cfg.ABACURL, time.Duration(*timeout)*time.Second)

	roles, err := listRoles(rolesParams{
		ctx:     context.Background(),
		org:     *org,
		harness: cfg.HarnessToken,
		abac:    client,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	if err := writeJSON(os.Stdout, RolesResponse{Roles: roles}); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	return 0
}
