package runtime

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/secrets"
)

type ModelInvokeRequest struct {
	Request   json.RawMessage `json:"request"`
	UserID    string          `json:"user_id"`
	RequestID string          `json:"request_id"`
}

type ModelInvokeResponse struct {
	Type    string          `json:"type"`
	Content json.RawMessage `json:"content,omitempty"`
	Error   string          `json:"error,omitempty"`
}

type ModelInvokeLog struct {
	RequestID  string `json:"request_id"`
	OrgID      string `json:"org_id"`
	AgentID    string `json:"agent_id"`
	UserID     string `json:"user_id"`
	ProfileID  string `json:"profile_id"`
	ModelID    string `json:"model_id"`
	Outcome    string `json:"outcome"`
	DurationMs int64  `json:"duration_ms"`
}

func logModelInvoke(logEntry ModelInvokeLog) {
	slog.Info("model_invoke",
		"request_id", logEntry.RequestID,
		"org_id", logEntry.OrgID,
		"agent_id", logEntry.AgentID,
		"user_id", logEntry.UserID,
		"profile_id", logEntry.ProfileID,
		"outcome", logEntry.Outcome,
		"duration_ms", logEntry.DurationMs,
	)
}

func GetModelProfileAPIKey(profile *ModelProfile) (string, error) {
	if profile.SecretRef == "" || profile.SecretBackend == "" {
		return "", nil
	}

	store, err := secrets.NewStore()
	if err != nil {
		return "", fmt.Errorf("failed to create secret store: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	apiKey, err := store.Get(ctx, profile.SecretBackend, profile.SecretRef)
	if err != nil {
		return "", fmt.Errorf("failed to get API key from backend: %w", err)
	}

	if apiKey == nil {
		return "", fmt.Errorf("API key not found in credential store")
	}

	return *apiKey, nil
}

func InvokeModelEndpoint(profile *ModelProfile, request json.RawMessage, requestID string) error {
	endpoint := profile.Endpoint + "/chat/completions"

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(string(request)))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	if profile.AuthType == "api_key" {
		apiKey, err := GetModelProfileAPIKey(profile)
		if err != nil {
			return fmt.Errorf("failed to get API key: %v", err)
		}
		if apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+apiKey)
		}
	}

	client := &http.Client{
		Timeout: 120 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("model endpoint is not responding. Please try again later.")
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("model authentication failed. Contact your admin.")
	}
	if resp.StatusCode >= 500 {
		return fmt.Errorf("model endpoint is not responding. Please try again later.")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("model request failed (status %d): %s", resp.StatusCode, string(body))
	}

	reader := bufio.NewReader(resp.Body)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("error reading response: %v", err)
		}

		os.Stdout.Write(line)
	}

	return nil
}
