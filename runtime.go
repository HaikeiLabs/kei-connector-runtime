package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// runRuntime provides the startup contract used by a Bot Runtime image. The
// proxy remains a one-shot CLI for tool authorization; the runtime image calls
// `runtime bootstrap` before starting its bot process and may run `heartbeat`
// alongside that process for liveness updates.
func runRuntime(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "runtime requires a subcommand: bootstrap or heartbeat")
		return 1
	}
	switch args[0] {
	case "bootstrap":
		return runRuntimeBootstrap(args[1:], os.Stdout, os.Stderr, configFromEnv(), NewRuntimeClient)
	case "heartbeat":
		return runRuntimeHeartbeat(args[1:], os.Stdout, os.Stderr, configFromEnv(), NewRuntimeClient)
	default:
		fmt.Fprintf(os.Stderr, "unknown runtime command %q\n", args[0])
		return 1
	}
}

type runtimeClientFactory func(baseURL string, timeout time.Duration) RuntimeClient

// runtimeBootstrapOutput is what a harness reads to learn its own scope. OrgID
// and WorkspaceID come from the authenticating harness key, which is minted per
// (workspace, harness) and is the authority for its scope (ADR 014). A harness
// discovers them here rather than being configured with them, so there is no
// second source of truth to drift.
//
// WorkspaceID is omitted for a legacy key minted before the workspace boundary.
// A consumer that requires a workspace should treat its absence as an error and
// have the key re-minted, not fall back to an organization-wide scope.
type runtimeBootstrapOutput struct {
	InstallationID string  `json:"installation_id"`
	OrgID          string  `json:"org_id"`
	WorkspaceID    *string `json:"workspace_id,omitempty"`
	Platform       string  `json:"platform"`
	Status         string  `json:"status"`
	BindingStatus  string  `json:"binding_status"`
}

func runRuntimeBootstrap(args []string, stdout, stderr io.Writer, cfg Config, newClient runtimeClientFactory) int {
	flags := flag.NewFlagSet("runtime bootstrap", flag.ContinueOnError)
	flags.SetOutput(stderr)
	timeout := flags.Duration("timeout", 15*time.Second, "control-plane request timeout")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *timeout <= 0 {
		fmt.Fprintln(stderr, "runtime bootstrap accepts no positional arguments and requires a positive --timeout")
		return 2
	}
	identity, err := bootstrapRuntimeWithClient(context.Background(), cfg, *timeout, newClient)
	if err != nil {
		fmt.Fprintf(stderr, "runtime bootstrap failed: %v\n", err)
		return 1
	}
	return writeRuntimeBootstrapOutput(stdout, identity, stderr)
}

func runRuntimeHeartbeat(args []string, stdout, stderr io.Writer, cfg Config, newClient runtimeClientFactory) int {
	flags := flag.NewFlagSet("runtime heartbeat", flag.ContinueOnError)
	flags.SetOutput(stderr)
	timeout := flags.Duration("timeout", 15*time.Second, "control-plane request timeout")
	interval := flags.Duration("interval", time.Minute, "heartbeat interval")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *timeout <= 0 || *interval < time.Second {
		fmt.Fprintln(stderr, "runtime heartbeat accepts no positional arguments; --timeout must be positive and --interval must be at least one second")
		return 2
	}
	identity, err := bootstrapRuntimeWithClient(context.Background(), cfg, *timeout, newClient)
	if err != nil {
		fmt.Fprintf(stderr, "runtime heartbeat failed: %v\n", err)
		return 1
	}
	if code := writeRuntimeBootstrapOutput(stdout, identity, stderr); code != 0 {
		return code
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := maintainRuntimeHeartbeat(ctx, newClient(cfg.RuntimeControlPlaneURL, *timeout), cfg.RuntimeToken, cfg.RuntimeVersion, *interval); err != nil {
		fmt.Fprintf(stderr, "runtime heartbeat failed: %v\n", err)
		return 1
	}
	return 0
}

func bootstrapRuntimeWithClient(ctx context.Context, cfg Config, timeout time.Duration, newClient runtimeClientFactory) (*RuntimeIdentity, error) {
	if !cfg.IsRuntime() {
		return nil, errors.New("KEI_RUNTIME_TOKEN is required for runtime bootstrap")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	client := newClient(cfg.RuntimeControlPlaneURL, timeout)
	identity, err := client.WhoAmI(ctx, cfg.RuntimeToken)
	if err != nil {
		return nil, fmt.Errorf("resolve runtime installation: %w", err)
	}
	if identity == nil {
		return nil, errors.New("runtime identity response is incomplete")
	}
	if err := client.Heartbeat(ctx, cfg.RuntimeToken, cfg.RuntimeVersion); err != nil {
		return nil, fmt.Errorf("report runtime heartbeat: %w", err)
	}
	// Sync identity is optional for runtimes that have not yet been assigned a
	// credential store. Once configured, bootstrap registers it idempotently.
	if cfg.CredentialStoreInstallationID != "" && cfg.CredentialSyncKeyID != "" && cfg.CredentialSyncPrivateKey != "" {
		publicKey, err := credentialSyncPublicKey(cfg.CredentialSyncPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("derive credential sync public key: %w", err)
		}
		if err := client.RegisterCredentialSyncKey(ctx, cfg.RuntimeToken, cfg.CredentialStoreInstallationID, cfg.CredentialSyncKeyID, publicKey); err != nil {
			return nil, fmt.Errorf("register credential sync key: %w", err)
		}
	}
	return identity, nil
}

func maintainRuntimeHeartbeat(ctx context.Context, client RuntimeClient, token, version string, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := client.Heartbeat(ctx, token, version); err != nil {
				return fmt.Errorf("report runtime heartbeat: %w", err)
			}
		}
	}
}

func writeRuntimeBootstrapOutput(stdout io.Writer, identity *RuntimeIdentity, stderr io.Writer) int {
	if err := json.NewEncoder(stdout).Encode(runtimeBootstrapOutput{
		InstallationID: identity.ID,
		OrgID:          identity.OrgID,
		WorkspaceID:    identity.WorkspaceID,
		Platform:       identity.Platform,
		Status:         identity.Status,
		BindingStatus:  identity.BindingStatus,
	}); err != nil {
		fmt.Fprintf(stderr, "runtime bootstrap failed: write response: %v\n", err)
		return 1
	}
	return 0
}
