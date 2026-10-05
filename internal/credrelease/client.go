package credrelease

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var ErrSubjectUnauthorized = errors.New("subject token is not authorized")

type Client struct {
	baseURL      string
	runtimeToken string
	httpClient   *http.Client
}

func NewClient(baseURL, runtimeToken string) *Client {
	return &Client{
		baseURL:      strings.TrimRight(baseURL, "/"),
		runtimeToken: runtimeToken,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
	}
}

type resolveRequest struct {
	SubjectToken string `json:"subject_token"`
	ConnectorID  string `json:"connector_id"`
	Capability   string `json:"capability"`
}

type resolveResponse struct {
	Credential string `json:"credential"`
}

func (c *Client) Resolve(ctx context.Context, subjectToken, connectorID, capability string) (string, error) {
	body, err := json.Marshal(resolveRequest{
		SubjectToken: subjectToken,
		ConnectorID:  connectorID,
		Capability:   capability,
	})
	if err != nil {
		return "", fmt.Errorf("marshal resolve request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/connectorCredentials:resolve", strings.NewReader(string(body)))
	if err != nil {
		return "", fmt.Errorf("build resolve request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.runtimeToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("resolve request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return "", ErrSubjectUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("resolve returned status %d", resp.StatusCode)
	}

	var result resolveResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode resolve response: %w", err)
	}
	if result.Credential == "" {
		return "", fmt.Errorf("resolve returned empty credential")
	}
	return result.Credential, nil
}
