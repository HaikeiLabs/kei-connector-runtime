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

	client := NewControlPlaneModelProfileClient(cfg.RuntimeControlPlaneURL, cfg.RuntimeToken, 10*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	profile, err := resolveModelInvokeProfile(ctx, client, invokeReq.AgentID, invokeReq.ProfileID)
	if err != nil {
		sendError("failed to resolve model profile: " + err.Error())
		return 1
	}
	slog.Info("model_profile_selected", "org_id", profile.OrgID, "agent_id", profile.AgentID, "profile_id", profile.ProfileID, "source", "runtime_assignment")

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

func resolveModelInvokeProfile(ctx context.Context, client ControlPlaneModelProfileClient, agentID, profileID string) (*ModelProfile, error) {
	var profile *ModelProfile
	var err error
	if profileID != "" {
		profile, err = client.GetRuntimeModelProfileForAgent(ctx, profileID, agentID)
	} else if agentID != "" {
		profile, err = client.GetRuntimeAssignedModelProfileForAgent(ctx, agentID)
	} else {
		profile, err = client.GetRuntimeAssignedModelProfile(ctx)
	}
	if err == nil && profile == nil {
		return nil, fmt.Errorf("requested model profile is not assigned to the selected agent")
	}
	return profile, err
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
