package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type HarnessIdentity struct {
	OrgID          string `json:"org_id"`
	AgentID        string `json:"agent_id"`
	ModelProfileID string `json:"model_profile_id,omitempty"`
}

func resolveHarnessIdentity(ctx context.Context, baseURL, serviceSecret, harnessToken string) (*HarnessIdentity, error) {
	body, err := json.Marshal(map[string]string{"harness_token": harnessToken})
	if err != nil {
		return nil, fmt.Errorf("marshal harness identity request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/v1/internal/harness-identity", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build harness identity request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Application credential in X-KEI-API-Key; Authorization is reserved for
	// the platform transport layer (ADR-009).
	if serviceSecret != "" {
		req.Header.Set("X-KEI-API-Key", serviceSecret)
	}
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("harness identity request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("harness identity rejected (status %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("harness identity request failed (status %d)", resp.StatusCode)
	}
	var identity HarnessIdentity
	if err := json.NewDecoder(resp.Body).Decode(&identity); err != nil {
		return nil, fmt.Errorf("decode harness identity response: %w", err)
	}
	if identity.OrgID == "" || identity.AgentID == "" {
		return nil, fmt.Errorf("harness identity response is incomplete")
	}
	return &identity, nil
}
