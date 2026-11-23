package connectorruntime

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/secrets"
	"github.com/google/uuid"
)

// runModelProfile resolves a runtime model profile and, when applicable,
// reads its credential from the configured external secret store. The command
// is intended for a local runtime process such as Pedro; credentials are
// emitted only on stdout and are never logged by the proxy.
func runModelProfile(args []string) int {
	fs := flag.NewFlagSet("model profile", flag.ContinueOnError)
	agentID := fs.String("agent-id", "", "agent UUID whose assigned model profile to resolve")
	profileID := fs.String("profile-id", "", "model profile ID (must be assigned to the selected agent)")
	metadataOnly := fs.Bool("metadata-only", false, "return assigned model metadata without resolving or exposing credentials")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg := configFromEnv()
	if !cfg.IsRuntime() || cfg.RuntimeToken == "" || cfg.RuntimeControlPlaneURL == "" {
		fmt.Fprintln(os.Stderr, "model profile requires KEI_RUNTIME_TOKEN and KEI_RUNTIME_CONTROL_PLANE_URL")
		return 2
	}
	var requestedAgentID string
	if *agentID != "" {
		parsedAgentID, err := uuid.Parse(*agentID)
		if err != nil || parsedAgentID == uuid.Nil {
			fmt.Fprintln(os.Stderr, "model profile --agent-id must be a valid UUID")
			return 2
		}
		requestedAgentID = parsedAgentID.String()
	}
	client := NewControlPlaneModelProfileClient(cfg.RuntimeControlPlaneURL, cfg.RuntimeToken, 10*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var profile *ModelProfile
	var err error
	if *profileID != "" {
		parsedProfileID, parseErr := uuid.Parse(*profileID)
		if parseErr != nil || parsedProfileID == uuid.Nil {
			fmt.Fprintln(os.Stderr, "model profile --profile-id must be a valid UUID")
			return 2
		}
		fmt.Fprintln(os.Stderr, "model profile lookup: selected assigned profile")
		profile, err = client.GetRuntimeModelProfileForAgent(ctx, parsedProfileID.String(), requestedAgentID)
		if err == nil && profile == nil {
			err = fmt.Errorf("profile %q is not assigned to the selected agent", parsedProfileID)
		}
	} else if requestedAgentID == "" {
		fmt.Fprintln(os.Stderr, "model profile lookup: runtime default agent assignment")
		profile, err = client.GetRuntimeAssignedModelProfile(ctx)
	} else {
		fmt.Fprintln(os.Stderr, "model profile lookup: requested agent assignment")
		profile, err = client.GetRuntimeAssignedModelProfileForAgent(ctx, requestedAgentID)
	}
	if err == nil && profile == nil {
		if requestedAgentID == "" {
			err = fmt.Errorf("runtime has no active model profile assigned to its default agent (or has no default agent assigned)")
		} else {
			err = fmt.Errorf("runtime has no active model profile assigned to the selected agent")
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "model profile resolution failed: %v\n", err)
		return 1
	}
	if profile == nil {
		fmt.Fprintln(os.Stderr, "model profile not found")
		return 2
	}
	if profile.Status != "active" {
		fmt.Fprintln(os.Stderr, "model profile is not active")
		return 2
	}
	if *metadataOnly {
		// Callers configuring an external credential source need no secret-store
		// access or backend references. Keep the same assignment checks above.
		metadata := *profile
		metadata.SecretBackend = ""
		metadata.SecretRef = ""
		metadata.CredentialStoreInstallation = ""
		if err := json.NewEncoder(os.Stdout).Encode(metadata); err != nil {
			fmt.Fprintf(os.Stderr, "write model profile metadata: %v\n", err)
			return 1
		}
		return 0
	}
	response := struct {
		*ModelProfile
		APIKey string `json:"api_key,omitempty"`
	}{ModelProfile: profile}
	if profile.AuthType == "api_key" {
		store, storeErr := secrets.NewStoreFromEnv()
		if storeErr != nil {
			fmt.Fprintf(os.Stderr, "model profile credential store unavailable: %v\n", storeErr)
			return 1
		}
		value, getErr := store.Get(ctx, profile.SecretBackend, profile.SecretRef)
		if getErr != nil || value == nil {
			fmt.Fprintf(os.Stderr, "model profile credential unavailable: %v\n", getErr)
			return 1
		}
		response.APIKey = *value
	}
	if err := json.NewEncoder(os.Stdout).Encode(response); err != nil {
		fmt.Fprintf(os.Stderr, "write model profile response: %v\n", err)
		return 1
	}
	return 0
}

func runModelProfiles(args []string) int {
	fs := flag.NewFlagSet("model profiles", flag.ContinueOnError)
	agentID := fs.String("agent-id", "", "agent UUID whose assigned model profiles to list")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg := configFromEnv()
	if !cfg.IsRuntime() || cfg.RuntimeToken == "" || cfg.RuntimeControlPlaneURL == "" {
		fmt.Fprintln(os.Stderr, "model profiles requires KEI_RUNTIME_TOKEN and KEI_RUNTIME_CONTROL_PLANE_URL")
		return 2
	}
	requestedAgentID := ""
	if *agentID != "" {
		parsedAgentID, err := uuid.Parse(*agentID)
		if err != nil || parsedAgentID == uuid.Nil {
			fmt.Fprintln(os.Stderr, "model profiles --agent-id must be a valid UUID")
			return 2
		}
		requestedAgentID = parsedAgentID.String()
	}
	client := NewControlPlaneModelProfileClient(cfg.RuntimeControlPlaneURL, cfg.RuntimeToken, 10*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	profiles, err := client.ListRuntimeModelProfiles(ctx, requestedAgentID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "model profile list failed: %v\n", err)
		return 1
	}
	if err := json.NewEncoder(os.Stdout).Encode(profiles); err != nil {
		fmt.Fprintf(os.Stderr, "write model profile list: %v\n", err)
		return 1
	}
	return 0
}
