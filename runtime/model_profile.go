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
	IsDefault                   bool   `json:"is_default"`
}

type ModelProfileSummary struct {
	ProfileID    string `json:"profile_id"`
	DisplayName  string `json:"display_name"`
	DefaultModel string `json:"default_model"`
	Endpoint     string `json:"endpoint"`
	AuthType     string `json:"auth_type"`
	Status       string `json:"status"`
	IsDefault    bool   `json:"is_default"`
}

type ModelProfileList struct {
	ModelProfiles []ModelProfileSummary `json:"model_profiles"`
}

type ControlPlaneModelProfileClient interface {
	GetRuntimeModelProfile(ctx context.Context, profileID string) (*ModelProfile, error)
	GetRuntimeModelProfileForAgent(ctx context.Context, profileID, agentID string) (*ModelProfile, error)
	ListRuntimeModelProfiles(ctx context.Context, agentID string) (*ModelProfileList, error)
	GetRuntimeDefaultModelProfile(ctx context.Context) (*ModelProfile, error)
	GetRuntimeAssignedModelProfile(ctx context.Context) (*ModelProfile, error)
	GetRuntimeAssignedModelProfileForAgent(ctx context.Context, agentID string) (*ModelProfile, error)
}

func (c *controlPlaneModelProfileClient) GetRuntimeDefaultModelProfile(ctx context.Context) (*ModelProfile, error) {
	return c.getRuntimeModelProfile(ctx, c.baseURL+"/api/v1/runtime/model-profiles/default")
}

func (c *controlPlaneModelProfileClient) GetRuntimeAssignedModelProfile(ctx context.Context) (*ModelProfile, error) {
	return c.getRuntimeAssignedModelProfile(ctx, "")
}

func (c *controlPlaneModelProfileClient) GetRuntimeAssignedModelProfileForAgent(ctx context.Context, agentID string) (*ModelProfile, error) {
	parsedAgentID, err := uuid.Parse(agentID)
	if err != nil || parsedAgentID == uuid.Nil {
		return nil, fmt.Errorf("invalid agent ID")
	}
	return c.getRuntimeAssignedModelProfile(ctx, parsedAgentID.String())
}

func (c *controlPlaneModelProfileClient) getRuntimeAssignedModelProfile(ctx context.Context, agentID string) (*ModelProfile, error) {
	endpoint := c.baseURL + "/api/v1/runtime/model-profiles/assigned"
	if agentID != "" {
		endpoint += "?agent_id=" + url.QueryEscape(agentID)
	}
	profile, err := c.getRuntimeModelProfile(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	if profile == nil {
		return nil, fmt.Errorf("runtime has no active model profile assigned to the requested agent")
	}
	if profile.AgentID == "" || profile.AgentID == uuid.Nil.String() {
		return nil, fmt.Errorf("runtime assigned-profile response has no valid assigned agent")
	}
	if agentID != "" && profile.AgentID != agentID {
		return nil, fmt.Errorf("runtime assigned-profile response agent ID does not match the requested agent")
	}
	if profile.ProfileID == "" || profile.ProfileID == uuid.Nil.String() {
		return nil, fmt.Errorf("runtime agent has no valid active assigned model profile")
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
	return c.GetRuntimeModelProfileForAgent(ctx, profileID, "")
}

func (c *controlPlaneModelProfileClient) GetRuntimeModelProfileForAgent(ctx context.Context, profileID, agentID string) (*ModelProfile, error) {
	parsedProfileID, err := uuid.Parse(profileID)
	if err != nil || parsedProfileID == uuid.Nil {
		return nil, fmt.Errorf("invalid model profile ID")
	}
	endpoint := c.baseURL + "/api/v1/runtime/model-profiles/" + url.PathEscape(parsedProfileID.String())
	requestedAgentID := ""
	if agentID != "" {
		parsedAgentID, parseErr := uuid.Parse(agentID)
		if parseErr != nil || parsedAgentID == uuid.Nil {
			return nil, fmt.Errorf("invalid agent ID")
		}
		requestedAgentID = parsedAgentID.String()
		endpoint += "?agent_id=" + url.QueryEscape(requestedAgentID)
	}
	profile, err := c.getRuntimeModelProfile(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	if profile != nil && requestedAgentID != "" && profile.AgentID != requestedAgentID {
		return nil, fmt.Errorf("runtime model-profile response agent ID does not match the requested agent")
	}
	return profile, nil
}

func (c *controlPlaneModelProfileClient) ListRuntimeModelProfiles(ctx context.Context, agentID string) (*ModelProfileList, error) {
	endpoint := c.baseURL + "/api/v1/runtime/model-profiles"
	if agentID != "" {
		parsedAgentID, err := uuid.Parse(agentID)
		if err != nil || parsedAgentID == uuid.Nil {
			return nil, fmt.Errorf("invalid agent ID")
		}
		endpoint += "?agent_id=" + url.QueryEscape(parsedAgentID.String())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build model profile list request: %w", err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("model profile list request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("model profile list auth failed (status %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("model profile list request failed (status %d)", resp.StatusCode)
	}
	var result ModelProfileList
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("unmarshal model profile list response: %w", err)
	}
	if result.ModelProfiles == nil {
		result.ModelProfiles = []ModelProfileSummary{}
	}
	return &result, nil
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
		IsDefault                     bool       `json:"is_default"`
		CredentialStoreInstallationID *uuid.UUID `json:"credential_store_installation_id,omitempty"`
		SecretBackend                 string     `json:"secret_backend"`
		SecretRef                     string     `json:"secret_ref,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return nil, fmt.Errorf("unmarshal model profile response: %w", err)
	}

	result := &ModelProfile{
		ProfileID:     profile.ID.String(),
		OrgID:         profile.OrgID.String(),
		DisplayName:   profile.DisplayName,
		Endpoint:      profile.Endpoint,
		DefaultModel:  profile.DefaultModel,
		AuthType:      profile.AuthType,
		Status:        profile.Status,
		IsDefault:     profile.IsDefault,
		SecretRef:     profile.SecretRef,
		SecretBackend: profile.SecretBackend,
	}
	if profile.CredentialStoreInstallationID != nil {
		result.CredentialStoreInstallation = profile.CredentialStoreInstallationID.String()
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
