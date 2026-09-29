package connectorruntime

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/credentials"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/secrets"
)

// runCredential provides credential management commands including sync.
// The sync command processes pending credential deliveries from the control plane,
// writes them to the configured external backend (Azure Key Vault or AWS Secrets Manager),
// and acknowledges the result.
func runCredential(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "credential requires a subcommand: sync")
		return 1
	}
	switch args[0] {
	case "sync":
		return runCredentialSync(args[1:], os.Stdout, os.Stderr, configFromEnv())
	default:
		fmt.Fprintf(os.Stderr, "unknown credential command %q\n", args[0])
		return 1
	}
}

func runCredentialSync(args []string, stdout, stderr io.Writer, cfg Config) int {
	flags := flag.NewFlagSet("credential sync", flag.ContinueOnError)
	flags.SetOutput(stderr)
	timeout := flags.Duration("timeout", 30*time.Second, "control-plane request timeout")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *timeout <= 0 {
		fmt.Fprintln(stderr, "credential sync accepts no positional arguments and requires a positive --timeout")
		return 2
	}

	// Validate runtime configuration
	if !cfg.IsRuntime() {
		fmt.Fprintln(stderr, "credential sync requires KEI_RUNTIME_TOKEN to be set")
		return 1
	}
	if cfg.RuntimeControlPlaneURL == "" {
		fmt.Fprintln(stderr, "credential sync requires KEI_RUNTIME_CONTROL_PLANE_URL to be set")
		return 1
	}
	if cfg.CredentialSyncKeyID == "" || cfg.CredentialSyncPrivateKey == "" {
		fmt.Fprintln(stderr, "credential sync requires KEI_CREDENTIAL_SYNC_KEY_ID and KEI_CREDENTIAL_SYNC_PRIVATE_KEY")
		return 1
	}

	// Create secret store (for backend operations)
	store, err := secrets.NewStore()
	if err != nil {
		fmt.Fprintf(stderr, "credential sync failed: create secret store: %v\n", err)
		return 1
	}

	// Run the sync
	runtimeClient := NewRuntimeClient(cfg.RuntimeControlPlaneURL, *timeout)
	output, err := credentials.Sync(context.Background(), credentials.Config{
		ControlPlaneURL: cfg.RuntimeControlPlaneURL,
		RuntimeToken:    cfg.RuntimeToken,
		KeyID:           cfg.CredentialSyncKeyID,
		PrivateKey:      cfg.CredentialSyncPrivateKey,
		Timeout:         *timeout,
	}, store, func(ctx context.Context) (string, error) {
		identity, err := runtimeClient.WhoAmI(ctx, cfg.RuntimeToken)
		if err != nil {
			return "", err
		}
		return identity.ID, nil
	})
	if err != nil {
		fmt.Fprintf(stderr, "credential sync failed: %v\n", err)
		return 1
	}

	// Write output (never outputs plaintext credentials)
	if err := json.NewEncoder(stdout).Encode(output); err != nil {
		fmt.Fprintf(stderr, "credential sync failed: write output: %v\n", err)
		return 1
	}

	return 0
}
