package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// cachedToken holds a cached OAuth token response with expiration.
type cachedToken struct {
	response *OAuthTokenResponse
	expires  time.Time
}

type oidcBridgeClient struct {
	baseURL string
	secret  string
	client  *http.Client
	// Cache for OAuth tokens with single-flight
	cache    map[string]cachedToken
	cacheMu  sync.RWMutex
	sfGroup  singleflight.Group
	cacheTTL time.Duration
}

func NewOIDCBridgeClient(baseURL, secret string, timeout time.Duration) OIDCTokenProvider {
	return &oidcBridgeClient{
		baseURL:  baseURL,
		secret:   secret,
		client:   &http.Client{Timeout: timeout},
		cache:    make(map[string]cachedToken),
		cacheTTL: 5 * time.Minute, // Default cache TTL
	}
}

func (c *oidcBridgeClient) GetOAuthToken(ctx context.Context, userID, provider string) (*OAuthTokenResponse, error) {
	cacheKey := userID + "/" + provider

	// Check cache first
	c.cacheMu.RLock()
	cached, ok := c.cache[cacheKey]
	if ok && time.Now().Before(cached.expires) {
		c.cacheMu.RUnlock()
		return cached.response, nil
	}
	c.cacheMu.RUnlock()

	// Use single-flight to prevent thundering herd
	resp, err, _ := c.sfGroup.Do(cacheKey, func() (interface{}, error) {
		return c.fetchToken(ctx, userID, provider)
	})

	if err != nil {
		return nil, err
	}

	if resp, ok := resp.(*OAuthTokenResponse); ok && resp != nil {
		// Update cache
		c.cacheMu.Lock()
		c.cache[cacheKey] = cachedToken{
			response: resp,
			expires:  time.Now().Add(c.cacheTTL),
		}
		c.cacheMu.Unlock()
	}

	return resp.(*OAuthTokenResponse), err
}

func (c *oidcBridgeClient) fetchToken(ctx context.Context, userID, provider string) (*OAuthTokenResponse, error) {
	endpoint := c.baseURL + "/oauth/credentials/" + url.PathEscape(userID) + "/" + url.PathEscape(provider)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, ErrEnrollmentRequired // Bridge unreachable = enrollment required
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.secret)

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, ErrEnrollmentRequired // Bridge unreachable = enrollment required
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, ErrEnrollmentRequired // 404 = no token, need enrollment
	case http.StatusConflict:
		return nil, ErrEnrollmentRequired // 409 = refresh failed, need re-enrollment
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("OIDC bridge rejected credentials (status %d)", resp.StatusCode)
	default:
		return nil, ErrEnrollmentRequired // Other errors = enrollment required
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ErrEnrollmentRequired
	}

	var tokenResp OAuthTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, ErrEnrollmentRequired
	}

	return &tokenResp, nil
}
