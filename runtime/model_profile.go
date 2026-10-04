package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
)

type ModelProfile struct {
	ProfileID                   string `json:"profile_id"`
	OrgID                       string `json:"org_id"`
	AgentID                     string `json:"agent_id,omitempty"`
	DisplayName                 string `json:"display_name"`
	Endpoint                    string `json:"endpoint"`
	DefaultModel                string `json:"default_model"`
	AuthType                    string `json:"auth_type"`
	Status                      string `json:"status"`
	SecretBackend               string `json:"secret_backend,omitempty"`
	SecretRef                   string `json:"secret_ref,omitempty"`
	CredentialStoreInstallation string `json:"credential_store_installation_id,omitempty"`
}

type ControlPlaneModelProfileClient interface {
	GetRuntimeModelProfile(ctx context.Context, profileID string) (*ModelProfile, error)
	GetRuntimeDefaultModelProfile(ctx context.Context) (*ModelProfile, error)
	GetRuntimeAssignedModelProfile(ctx context.Context) (*ModelProfile, error)
}

func (c *controlPlaneModelProfileClient) GetRuntimeDefaultModelProfile(ctx context.Context) (*ModelProfile, error) {
	return c.getRuntimeModelProfile(ctx, c.baseURL+"/api/v1/runtime/model-profiles/default")
}

func (c *controlPlaneModelProfileClient) GetRuntimeAssignedModelProfile(ctx context.Context) (*ModelProfile, error) {
	profile, err := c.getRuntimeModelProfile(ctx, c.baseURL+"/api/v1/runtime/model-profiles/assigned")
	if err != nil {
		return nil, err
	}
	if profile == nil {
		return nil, fmt.Errorf("runtime has no active model profile assigned to its default agent (or has no default agent assigned)")
	}
	if profile.AgentID == "" || profile.AgentID == uuid.Nil.String() {
		return nil, fmt.Errorf("runtime assigned-profile response has no valid default assigned agent")
	}
	if profile.ProfileID == "" || profile.ProfileID == uuid.Nil.String() {
		return nil, fmt.Errorf("runtime default agent has no valid active assigned model profile")
	}
	return profile, nil
}

type controlPlaneModelProfileClient struct {
	baseURL string
	token   string
	client  *http.Client
}

func NewControlPlaneModelProfileClient(baseURL, token string, timeout time.Duration) ControlPlaneModelProfileClient {
	return &controlPlaneModelProfileClient{
		baseURL: baseURL,
		token:   token,
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *controlPlaneModelProfileClient) GetRuntimeModelProfile(ctx context.Context, profileID string) (*ModelProfile, error) {
	endpoint := c.baseURL + "/api/v1/runtime/model-profiles/" + url.PathEscape(profileID)
	return c.getRuntimeModelProfile(ctx, endpoint)
}

func (c *controlPlaneModelProfileClient) getRuntimeModelProfile(ctx context.Context, endpoint string) (*ModelProfile, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build model profile request: %w", err)
	}
	if c.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("model profile request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("model profile auth failed (status %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("model profile request failed (status %d)", resp.StatusCode)
	}

	var profile struct {
		ID                            uuid.UUID  `json:"profile_id"`
		OrgID                         uuid.UUID  `json:"org_id"`
		AgentID                       *uuid.UUID `json:"agent_id,omitempty"`
		DisplayName                   string     `json:"display_name"`
		Endpoint                      string     `json:"endpoint"`
		DefaultModel                  string     `json:"default_model"`
		AuthType                      string     `json:"auth_type"`
		Status                        string     `json:"status"`
		CredentialStoreInstallationID uuid.UUID  `json:"credential_store_installation_id"`
		SecretBackend                 string     `json:"secret_backend"`
		SecretRef                     string     `json:"secret_ref,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return nil, fmt.Errorf("unmarshal model profile response: %w", err)
	}

	result := &ModelProfile{
		ProfileID:                   profile.ID.String(),
		OrgID:                       profile.OrgID.String(),
		DisplayName:                 profile.DisplayName,
		Endpoint:                    profile.Endpoint,
		DefaultModel:                profile.DefaultModel,
		AuthType:                    profile.AuthType,
		Status:                      profile.Status,
		SecretRef:                   profile.SecretRef,
		SecretBackend:               profile.SecretBackend,
		CredentialStoreInstallation: profile.CredentialStoreInstallationID.String(),
	}
	if profile.AgentID != nil {
		result.AgentID = profile.AgentID.String()
	}

	return result, nil
}

/* legacyCredentialAdminModelProfileClient removed.
func (c *modelProfileClient) GetModelProfileByID(ctx context.Context, orgID, profileID string) (*ModelProfile, error) {
	endpoint := c.baseURL + "/api/v1/model-profiles/" + url.PathEscape(profileID) + "/resolve?org_id=" + url.QueryEscape(orgID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build model profile request: %w", err)
	}
	if c.secret != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.secret)
	}
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("model profile request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("model profile auth failed (status %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("model profile request failed (status %d)", resp.StatusCode)
	}
	var profile ModelProfile
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return nil, fmt.Errorf("unmarshal model profile response: %w", err)
	}
	return &profile, nil
}
*/

/* type modelProfileClient struct {
	baseURL string
	secret  string
	client  *http.Client
}
*/

// NewModelProfileClient creates a new client for fetching model profiles
/* func NewModelProfileClient(baseURL, secret string, timeout time.Duration) ModelProfileClient {
	return &modelProfileClient{
		baseURL: baseURL,
		secret:  secret,
		client:  &http.Client{Timeout: timeout},
	}
}
*/

// GetModelProfile fetches the active model profile for an org/agent combination
/* func (c *modelProfileClient) GetModelProfile(ctx context.Context, orgID, agentID string) (*ModelProfile, error) {
	endpoint := c.baseURL + "/api/v1/model-profiles/resolve/" + url.PathEscape(orgID) + "/" + url.PathEscape(agentID)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build model profile request: %w", err)
	}
	if c.secret != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.secret)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("model profile request failed: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("model profile auth failed (status %d)", resp.StatusCode)
	default:
		return nil, fmt.Errorf("model profile request failed (status %d)", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read model profile response: %w", err)
	}

	var profile ModelProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, fmt.Errorf("unmarshal model profile response: %w", err)
	}

	return &profile, nil
}
*/
