package connectorruntime

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/secrets"
)

// runModelProfile resolves a runtime model profile and, when applicable,
// reads its credential from the configured external secret store. The command
// is intended for a local runtime process such as Pedro; credentials are
// emitted only on stdout and are never logged by the proxy.
func runModelProfile(args []string) int {
	fs := flag.NewFlagSet("model profile", flag.ContinueOnError)
	profileID := fs.String("profile-id", "", "model profile ID (must be assigned to the runtime's default agent)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg := configFromEnv()
	if !cfg.IsRuntime() || cfg.RuntimeToken == "" || cfg.RuntimeControlPlaneURL == "" {
		fmt.Fprintln(os.Stderr, "model profile requires KEI_RUNTIME_TOKEN and KEI_RUNTIME_CONTROL_PLANE_URL")
		return 2
	}
	client := NewControlPlaneModelProfileClient(cfg.RuntimeControlPlaneURL, cfg.RuntimeToken, 10*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var profile *ModelProfile
	var err error
	fmt.Fprintln(os.Stderr, "model profile lookup: runtime default agent assignment")
	profile, err = client.GetRuntimeAssignedModelProfile(ctx)
	if err == nil && profile == nil {
		err = fmt.Errorf("runtime has no active model profile assigned to its default agent (or has no default agent assigned)")
	}
	if err == nil && *profileID != "" {
		// The assigned-profile endpoint validates the runtime's workspace and
		// default-agent scope. Permit an explicit ID only when it is exactly
		// that authorized assignment; never resolve arbitrary profile IDs here.
		if profile.ProfileID != *profileID {
			err = fmt.Errorf("profile %q is not assigned to the runtime's default agent", *profileID)
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
	response := struct {
		*ModelProfile
		APIKey string `json:"api_key,omitempty"`
	}{ModelProfile: profile}
	if profile.AuthType == "api_key" {
		store, storeErr := secrets.NewStore()
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
