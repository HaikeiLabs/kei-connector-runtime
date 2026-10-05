package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"
)

// RunIdentity dispatches platform-neutral identity operations.
func RunIdentity(args []string, stdout, stderr io.Writer, cfg RuntimeConfig, newClient RuntimeClientFactory) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "identity requires a subcommand: link")
		return 2
	}
	switch args[0] {
	case "link":
		return runIdentityLink(args[1:], stdout, stderr, cfg, newClient)
	case "status":
		return RunIdentityStatus(args[1:], stdout, stderr, cfg, newClient)
	default:
		fmt.Fprintf(stderr, "unknown identity command %q\n", args[0])
		return 2
	}
}

func writeIdentityStatusDiagnostic(stderr io.Writer, category string, status int) {
	switch category {
	case IdentityStatusFailurePreTransport, IdentityStatusFailureTransport, IdentityStatusFailureResponse:
		fmt.Fprintf(stderr, "identity status diagnostic category=%s\n", category)
	case IdentityStatusFailureHTTP:
		if status >= 100 && status <= 599 {
			fmt.Fprintf(stderr, "identity status diagnostic category=%s http_status=%d\n", category, status)
		}
	}
}

func RunIdentityStatus(args []string, stdout, stderr io.Writer, cfg RuntimeConfig, newClient RuntimeClientFactory) int {
	flags := flag.NewFlagSet("identity status", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	platformUserID := flags.String("platform-user-id", "", "stable user ID from the current platform interaction")
	tenantID := flags.String("tenant-id", "", "platform tenant ID when the user ID is tenant-scoped")
	timeout := flags.Duration("timeout", 8*time.Second, "control-plane request timeout")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *timeout <= 0 || strings.TrimSpace(*platformUserID) == "" {
		fmt.Fprintln(stderr, "identity status invocation invalid")
		writeIdentityStatusDiagnostic(stderr, IdentityStatusFailurePreTransport, 0)
		return 2
	}
	if !cfg.IsRuntime() || cfg.Validate() != nil {
		fmt.Fprintln(stderr, "identity status configuration unavailable")
		writeIdentityStatusDiagnostic(stderr, IdentityStatusFailurePreTransport, 0)
		return 1
	}
	client := newClient(cfg.ControlPlaneURL(), *timeout)
	statusClient, ok := client.(interface {
		ResolveIdentityStatus(context.Context, string, IdentityStatusRequest) (*IdentityStatusResponse, error)
	})
	if !ok {
		fmt.Fprintln(stderr, "identity status request failed")
		writeIdentityStatusDiagnostic(stderr, IdentityStatusFailurePreTransport, 0)
		return 1
	}
	result, err := statusClient.ResolveIdentityStatus(context.Background(), cfg.Token(), IdentityStatusRequest{PlatformUserID: *platformUserID, TenantID: *tenantID})
	if err != nil || result == nil {
		fmt.Fprintln(stderr, "identity status request failed")
		var failure *IdentityStatusFailureError
		if errors.As(err, &failure) {
			writeIdentityStatusDiagnostic(stderr, failure.Category, failure.HTTPStatusCode)
		}
		return 1
	}
	if json.NewEncoder(stdout).Encode(result) != nil {
		fmt.Fprintln(stderr, "identity status output failed")
		return 1
	}
	return 0
}

func runIdentityLink(args []string, stdout, stderr io.Writer, cfg RuntimeConfig, newClient RuntimeClientFactory) int {
	flags := flag.NewFlagSet("identity link", flag.ContinueOnError)
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
		fmt.Fprintln(stderr, "identity link requires --platform and --platform-user-id, accepts no positional arguments, and requires a positive --timeout")
		return 2
	}
	if !cfg.IsRuntime() {
		fmt.Fprintln(stderr, "identity link requires KEI_RUNTIME_TOKEN")
		return 1
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(stderr, "identity link configuration invalid: %v\n", err)
		return 1
	}
	client := newClient(cfg.ControlPlaneURL(), *timeout)
	result, err := client.StartIdentityClaim(context.Background(), cfg.Token(), IdentityClaimStartRequest{
		Platform:       *platform,
		TenantID:       *tenantID,
		PlatformUserID: *platformUserID,
	})
	if err != nil {
		fmt.Fprintln(stderr, "identity link failed: control-plane request error")
		return 1
	}
	if result == nil {
		fmt.Fprintln(stderr, "identity link failed: empty control-plane response")
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		fmt.Fprintln(stderr, "identity link failed: could not write response")
		return 1
	}
	return 0
}
