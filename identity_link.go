package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// runIdentityLink dispatches platform-neutral identity-link operations.
func runIdentityLink(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "identity-link requires a subcommand: begin")
		return 2
	}
	switch args[0] {
	case "begin":
		return runIdentityLinkBegin(args[1:], os.Stdout, os.Stderr, configFromEnv(), NewRuntimeClient)
	default:
		fmt.Fprintf(os.Stderr, "unknown identity-link command %q\n", args[0])
		return 2
	}
}

// runIdentityLinkBegin starts a claim using the authenticated runtime's
// authoritative installation and workspace scope. The claim URL is a bearer
// secret, so it is written only to stdout for the caller to deliver privately.
func runIdentityLinkBegin(args []string, stdout, stderr io.Writer, cfg Config, newClient runtimeClientFactory) int {
	flags := flag.NewFlagSet("identity-link begin", flag.ContinueOnError)
	flags.SetOutput(stderr)
	platform := flags.String("platform", "", "chat platform (discord, slack, or teams)")
	platformUserID := flags.String("platform-user-id", "", "stable user ID from the current platform interaction")
	tenantID := flags.String("tenant-id", "", "platform tenant ID when the user ID is tenant-scoped")
	// Leave room for CLI startup and output within Python harnesses' 10-second
	// subprocess deadline.
	timeout := flags.Duration("timeout", 8*time.Second, "control-plane request timeout")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *timeout <= 0 || strings.TrimSpace(*platform) == "" || strings.TrimSpace(*platformUserID) == "" {
		fmt.Fprintln(stderr, "identity-link begin requires --platform and --platform-user-id, accepts no positional arguments, and requires a positive --timeout")
		return 2
	}
	if !cfg.IsRuntime() {
		fmt.Fprintln(stderr, "identity-link begin requires KEI_RUNTIME_TOKEN")
		return 1
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(stderr, "identity-link begin configuration invalid: %v\n", err)
		return 1
	}
	client := newClient(cfg.RuntimeControlPlaneURL, *timeout)
	result, err := client.StartIdentityClaim(context.Background(), cfg.RuntimeToken, IdentityClaimStartRequest{
		Platform:       *platform,
		TenantID:       *tenantID,
		PlatformUserID: *platformUserID,
	})
	if err != nil {
		fmt.Fprintf(stderr, "identity-link begin failed: %v\n", err)
		return 1
	}
	if result == nil {
		fmt.Fprintln(stderr, "identity-link begin failed: empty control-plane response")
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		fmt.Fprintln(stderr, "identity-link begin failed: could not write response")
		return 1
	}
	return 0
}
