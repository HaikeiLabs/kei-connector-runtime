package credentials

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// deliveryClient handles delivery operations with the control plane
type deliveryClient interface {
	ClaimDelivery(ctx context.Context, token string, req claimRequest) (*claimResponse, error)
	AcknowledgeDelivery(ctx context.Context, token string, req ackRequest) error
}

type httpDeliveryClient struct {
	baseURL string
	client  *http.Client
}

// newDeliveryClient creates a new credential delivery client
func newDeliveryClient(baseURL string, timeout time.Duration) deliveryClient {
	return &httpDeliveryClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *httpDeliveryClient) ClaimDelivery(ctx context.Context, token string, req claimRequest) (*claimResponse, error) {
	endpoint := c.baseURL + "/api/v1/runtime/credential-delivery/claim"
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("claim delivery request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNoContent {
		return &claimResponse{NoDeliveryPending: true}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("claim delivery returned status %d", resp.StatusCode)
	}

	var result claimResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &result, nil
}

func (c *httpDeliveryClient) AcknowledgeDelivery(ctx context.Context, token string, req ackRequest) error {
	endpoint := c.baseURL + "/api/v1/runtime/credential-delivery/ack"
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("acknowledge delivery request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("acknowledge delivery returned status %d", resp.StatusCode)
	}

	return nil
}
