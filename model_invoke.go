package connectorruntime

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"

	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

type ModelInvokeRequest = keiruntime.ModelInvokeRequest
type ModelInvokeResponse = keiruntime.ModelInvokeResponse

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

	var invokeReq ModelInvokeRequest
	decoder := json.NewDecoder(os.Stdin)
	if err := decoder.Decode(&invokeReq); err != nil {
		sendError("invalid request body: " + err.Error())
		return 1
	}

	if invokeReq.RequestID == "" {
		invokeReq.RequestID = uuid.New().String()
	}

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

	err = keiruntime.InvokeModelEndpoint(profile, invokeReq.Request, invokeReq.RequestID)
	if err != nil {
		sendError(err.Error())
		return 1
	}

	return 0
}

func resolveOrgAgentFromHarness(harnessKey string) (*keiruntime.HarnessIdentity, error) {
	cfg := configFromEnv()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return keiruntime.ResolveHarnessIdentity(ctx, cfg.ABACURL, cfg.ABACSecret, harnessKey)
}

func getModelProfile(orgID, profileID string) (*ModelProfile, error) {
	cfg := configFromEnv()

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

func sendError(message string) {
	resp := ModelInvokeResponse{
		Type:  "error",
		Error: message,
	}
	jsonBytes, _ := json.Marshal(resp)
	fmt.Fprintln(os.Stderr, string(jsonBytes))
}

func getModelProfileAPIKey(profile *ModelProfile) (string, error) {
	return keiruntime.GetModelProfileAPIKey(profile)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
