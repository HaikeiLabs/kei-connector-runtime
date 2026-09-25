package connectorruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

const identityStatusResolvePath = "/api/v1/runtime/chat-identity-statuses:resolve"

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
		return nil, errors.New("invalid identity status request")
	}
	body, err := json.Marshal(input)
	if err != nil {
		return nil, errors.New("encode identity status request failed")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+identityStatusResolvePath, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("build identity status request failed")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, errors.New("identity status request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("identity status request failed")
	}
	var result IdentityStatusResponse
	decoder := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil || !identityStatuses[result.Status] {
		return nil, errors.New("invalid identity status response")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("invalid identity status response")
	}
	return &result, nil
}
