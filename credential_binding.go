package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CredentialDescriptor is non-secret metadata resolved from the Kei control
// plane. The secret value is fetched separately from the customer's store.
type CredentialDescriptor struct {
	ID                  string         `json:"id"`
	OrgID               string         `json:"org_id"`
	UserID              string         `json:"user_id"`
	Service             string         `json:"service"`
	SecretBackend       string         `json:"secret_backend"`
	SecretRef           string         `json:"secret_ref"`
	CredentialType      string         `json:"credential_type,omitempty"`
	InjectionType       string         `json:"injection_type,omitempty"`
	InjectionHeader     string         `json:"injection_header,omitempty"`
	InjectionQueryParam string         `json:"injection_query_param,omitempty"`
	Status              string         `json:"status"`
	Version             int            `json:"version"`
	Metadata            map[string]any `json:"metadata,omitempty"`
}

var errCredentialBindingNotFound = fmt.Errorf("credential binding not found")

type CredentialBindingClient interface {
	Resolve(ctx context.Context, runtimeToken, userID, service string) (*CredentialDescriptor, error)
}

type credentialBindingClient struct {
	baseURL string
	client  *http.Client
}

func NewCredentialBindingClient(baseURL string, timeout time.Duration) CredentialBindingClient {
	return &credentialBindingClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *credentialBindingClient) Resolve(ctx context.Context, runtimeToken, userID, service string) (*CredentialDescriptor, error) {
	if runtimeToken == "" {
		return nil, fmt.Errorf("runtime token is required")
	}
	endpoint := c.baseURL + "/api/v1/runtime/credential-bindings/" + url.PathEscape(userID) + "/" + url.PathEscape(service)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build credential binding request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+runtimeToken)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("credential binding request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, errCredentialBindingNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("credential binding request returned status %d", resp.StatusCode)
	}
	var descriptor CredentialDescriptor
	if err := json.NewDecoder(resp.Body).Decode(&descriptor); err != nil {
		return nil, fmt.Errorf("decode credential binding response: %w", err)
	}
	if descriptor.SecretBackend == "" || descriptor.SecretRef == "" || descriptor.Status != "active" {
		return nil, fmt.Errorf("credential binding response is incomplete")
	}
	return &descriptor, nil
}
