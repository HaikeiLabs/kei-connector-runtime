package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ModelInvokeRequest is the input from Pedro
type ModelInvokeRequest struct {
	Request   json.RawMessage `json:"request"`
	UserID    string          `json:"user_id"`
	RequestID string          `json:"request_id"`
}

// ModelInvokeResponse is the streaming response
type ModelInvokeResponse struct {
	Type    string          `json:"type"` // "chunk", "done", "error"
	Content json.RawMessage `json:"content,omitempty"`
	Error   string          `json:"error,omitempty"`
}

func runModelInvoke(args []string) int {
	fs := flag.NewFlagSet("model invoke", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return 1
	}
	cfg := configFromEnv()
	if cfg.RuntimeToken == "" {
		fmt.Fprintln(os.Stderr, "Error: KEI_RUNTIME_TOKEN is required")
		return 1
	}

	// Read request from stdin
	var invokeReq ModelInvokeRequest
	decoder := json.NewDecoder(os.Stdin)
	if err := decoder.Decode(&invokeReq); err != nil {
		sendError("invalid request body: " + err.Error())
		return 1
	}

	// Generate request_id if not provided
	if invokeReq.RequestID == "" {
		invokeReq.RequestID = uuid.New().String()
	}

	// ABAC authenticates the harness key and chooses the agent override or the
	// organization default profile. The proxy never trusts caller-supplied IDs.
	identity, err := resolveOrgAgentFromHarness(cfg.RuntimeToken)
	if err != nil {
		sendError("failed to resolve organization: " + err.Error())
		return 1
	}
	if identity.ModelProfileID == "" {
		sendError("no model configured for your organization. Contact your admin.")
		return 2
	}
	slog.Info("model_profile_selected", "org_id", identity.OrgID, "agent_id", identity.AgentID, "profile_id", identity.ModelProfileID, "source", "harness_identity")

	// Get model profile from the runtime control plane.
	profile, err := getModelProfile(identity.OrgID, identity.ModelProfileID)
	if err != nil {
		sendError(err.Error())
		return 1
	}
	if profile == nil {
		sendError("no model configured for your organization. Contact your admin.")
		return 2
	}

	if profile.Status != "active" {
		sendError("the configured model is currently unavailable. Contact your admin.")
		return 2
	}

	// Make outbound request to the model endpoint
	err = invokeModelEndpoint(profile, invokeReq.Request, invokeReq.RequestID)
	if err != nil {
		sendError(err.Error())
		return 1
	}

	return 0
}

func resolveOrgAgentFromHarness(harnessKey string) (*HarnessIdentity, error) {
	cfg := configFromEnv()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return resolveHarnessIdentity(ctx, cfg.ABACURL, cfg.ABACSecret, harnessKey)
}

func getModelProfile(orgID, profileID string) (*ModelProfile, error) {
	cfg := configFromEnv()

	// For runtime mode, use the control plane (ABAC) - new path
	if cfg.IsRuntime() {
		return getModelProfileFromControlPlane(cfg, orgID, profileID)
	}

	return nil, fmt.Errorf("runtime model profile access requires KEI_RUNTIME_TOKEN")
}

func getModelProfileFromControlPlane(cfg Config, orgID, profileID string) (*ModelProfile, error) {
	client := NewControlPlaneModelProfileClient(cfg.RuntimeControlPlaneURL, cfg.RuntimeToken, 10*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	profile, err := client.GetRuntimeModelProfile(ctx, profileID)
	if err != nil {
		return nil, fmt.Errorf("control plane unavailable: %v", err)
	}
	if profile == nil {
		return nil, nil
	}

	return profile, nil
}

// getModelProfileAPIKey fetches the API key from the credential store backend.
// It reads provider credentials from Azure Key Vault or AWS Secrets Manager.
func getModelProfileAPIKey(profile *ModelProfile) (string, error) {
	// Profiles without a secret reference do not require a provider key.
	if profile.SecretRef == "" || profile.SecretBackend == "" {
		// Legacy path: no secret store reference, this shouldn't happen for new profiles
		return "", nil
	}

	// Create secret store (uses workload identity)
	store, err := NewSecretStore()
	if err != nil {
		return "", fmt.Errorf("failed to create secret store: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Fetch the API key from the backend
	apiKey, err := store.Get(ctx, profile.SecretBackend, profile.SecretRef)
	if err != nil {
		return "", fmt.Errorf("failed to get API key from backend: %w", err)
	}

	if apiKey == nil {
		return "", fmt.Errorf("API key not found in credential store")
	}

	return *apiKey, nil
}

func invokeModelEndpoint(profile *ModelProfile, request json.RawMessage, requestID string) error {
	endpoint := profile.Endpoint + "/chat/completions"

	// Build the HTTP request
	req, err := http.NewRequest("POST", endpoint, strings.NewReader(string(request)))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Add API key if auth_type is api_key
	if profile.AuthType == "api_key" {
		apiKey, err := getModelProfileAPIKey(profile)
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

	// Stream the response
	reader := bufio.NewReader(resp.Body)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("error reading response: %v", err)
		}

		// Send the line directly to stdout (SSE format)
		os.Stdout.Write(line)
	}

	return nil
}

func sendError(message string) {
	resp := ModelInvokeResponse{
		Type:  "error",
		Error: message,
	}
	jsonBytes, _ := json.Marshal(resp)
	fmt.Fprintln(os.Stderr, string(jsonBytes))
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Log entry for audit
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

// logModelInvoke logs the invocation (no secrets)
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
