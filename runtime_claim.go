package connectorruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const identityClaimStartPath = "/api/identity/claims/start"

// IdentityClaimStartRequest carries the platform identity from the current
// harness interaction. TenantID is empty for platforms such as Discord whose
// subject is globally unique.
type IdentityClaimStartRequest struct {
	Platform       string `json:"platform"`
	TenantID       string `json:"tenant_id"`
	PlatformUserID string `json:"platform_user_id"`
}

// IdentityClaimStartResponse contains the private, bearer-bearing claim URL.
// Callers must deliver it only through the initiating user's private channel.
type IdentityClaimStartResponse struct {
	ClaimURL  string    `json:"claim_url"`
	ExpiresAt time.Time `json:"expires_at"`
}

// StartIdentityClaim starts a platform-neutral claim through the console's
// server-side proxy. The runtime credential is forwarded as Bearer auth; this
// client never knows or sends the console-only X-KEI-API-Key.
func (c *runtimeClient) StartIdentityClaim(ctx context.Context, token string, input IdentityClaimStartRequest) (*IdentityClaimStartResponse, error) {
	input.Platform = strings.ToLower(strings.TrimSpace(input.Platform))
	if !supportedClaimPlatform(input.Platform) || strings.TrimSpace(token) == "" || strings.TrimSpace(input.PlatformUserID) == "" {
		return nil, errors.New("invalid identity claim request")
	}
	body, err := json.Marshal(input)
	if err != nil {
		return nil, errors.New("encode identity claim request failed")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+identityClaimStartPath, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("build identity claim request failed")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(req)
	if err != nil {
		return nil, errors.New("identity claim request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("identity claim request returned status %d", response.StatusCode)
	}
	var result IdentityClaimStartResponse
	if err := json.NewDecoder(http.MaxBytesReader(nil, response.Body, 16<<10)).Decode(&result); err != nil {
		return nil, errors.New("decode identity claim response failed")
	}
	claimURL, err := url.Parse(result.ClaimURL)
	if err != nil || (claimURL.Scheme != "https" && claimURL.Scheme != "http") || claimURL.Host == "" || !strings.Contains(claimURL.Fragment, "claim=") || result.ExpiresAt.IsZero() {
		return nil, errors.New("identity claim response is incomplete")
	}
	return &result, nil
}

func supportedClaimPlatform(platform string) bool {
	switch platform {
	case "discord", "slack", "teams":
		return true
	default:
		return false
	}
}
