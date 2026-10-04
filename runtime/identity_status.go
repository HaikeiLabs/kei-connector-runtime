package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const identityStatusResolvePath = "/api/v1/runtime/chat-identity-statuses:resolve"

// IdentityStatusFailureError contains only safe failure metadata. Its Error
// method intentionally remains generic; callers may inspect Category and
// HTTPStatusCode without exposing request or response contents.
type IdentityStatusFailureError struct {
	Category       string
	HTTPStatusCode int
}

const (
	IdentityStatusFailurePreTransport = "pre_transport"
	IdentityStatusFailureTransport    = "transport_error"
	IdentityStatusFailureHTTP         = "http_response"
	IdentityStatusFailureResponse     = "response_validation"
)

func (e *IdentityStatusFailureError) Error() string { return "identity status request failed" }

type IdentityStatusRequest struct {
	PlatformUserID string `json:"platform_user_id"`
	TenantID       string `json:"tenant_id"`
}

type IdentityStatusResponse struct {
	Status              string `json:"status"`
	AccessRequestStatus string `json:"access_request_status,omitempty"`
	DenialReason        string `json:"denial_reason,omitempty"`
	Retryable           *bool  `json:"retryable,omitempty"`
}

var identityStatuses = map[string]bool{
	"unlinked": true, "linked_pending": true, "linked_approved": true,
	"linked_denied": true, "linked_unapproved": true,
	"linked_approved_other_workspace": true, "retry": true, "service_error": true,
}

func (c *runtimeClient) ResolveIdentityStatus(ctx context.Context, token string, input IdentityStatusRequest) (*IdentityStatusResponse, error) {
	if strings.TrimSpace(token) == "" || strings.TrimSpace(input.PlatformUserID) == "" {
		return nil, &IdentityStatusFailureError{Category: IdentityStatusFailurePreTransport}
	}
	endpoint := c.baseURL + identityStatusResolvePath
	parsedURL, err := url.Parse(endpoint)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" || parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return nil, &IdentityStatusFailureError{Category: IdentityStatusFailurePreTransport}
	}
	body, err := json.Marshal(input)
	if err != nil {
		return nil, &IdentityStatusFailureError{Category: IdentityStatusFailurePreTransport}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, &IdentityStatusFailureError{Category: IdentityStatusFailurePreTransport}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
			return nil, &IdentityStatusFailureError{Category: IdentityStatusFailureHTTP, HTTPStatusCode: resp.StatusCode}
		}
		return nil, &IdentityStatusFailureError{Category: IdentityStatusFailureTransport}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &IdentityStatusFailureError{Category: IdentityStatusFailureHTTP, HTTPStatusCode: resp.StatusCode}
	}
	var result IdentityStatusResponse
	decoder := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil || !identityStatuses[result.Status] {
		return nil, &IdentityStatusFailureError{Category: IdentityStatusFailureResponse}
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, &IdentityStatusFailureError{Category: IdentityStatusFailureResponse}
	}
	return &result, nil
}
