package runtime

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

// RunPolicySync fetches the installation's bundle once over HTTPS with the
// runtime token, validates it against kei.policy-bundle/v1 and persists it
// atomically (0600) in KEI_RUNTIME_STATE_DIR, then prints `policy show`.
func RunPolicySync(ctx context.Context, args []string, stdout, stderr io.Writer, cfg PolicyConfig, identityFunc IdentityFunc, syncBundle SyncBundleFunc, checkRevocation func(error) bool, revokeState func()) int {
	fs := flag.NewFlagSet("policy sync", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if !cfg.IsRuntime() {
		fmt.Fprintln(stderr, "Error: KEI_RUNTIME_TOKEN is required")
		return 1
	}
	identity, err := identityFunc()
	if err != nil {
		if checkRevocation(err) {
			revokeState()
		}
		fmt.Fprintf(stderr, "Error: runtime identity unavailable: %v\n", err)
		return 1
	}
	syncErr := syncBundle(identity)
	if syncErr != nil {
		fmt.Fprintf(stderr, "Error: policy bundle sync failed: %v\n", syncErr)
	}
	status, err := PolicyStatus(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if err := WriteJSON(stdout, status); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if syncErr != nil || (status.State != policybundle.Active && status.State != policybundle.Stale) {
		return 1
	}
	return 0
}

// RunPolicyShow prints the persisted bundle's metadata and enforcement state
// with no network call. It exits 1 unless the bundle would be enforced.
func RunPolicyShow(args []string, stdout, stderr io.Writer, cfg PolicyConfig) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "policy show does not accept arguments")
		return 1
	}
	status, err := PolicyStatus(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if err := WriteJSON(stdout, status); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if status.State != policybundle.Active && status.State != policybundle.Stale {
		return 1
	}
	return 0
}

// PolicyStatus returns the persisted bundle's metadata and enforcement state.
func PolicyStatus(cfg PolicyConfig) (policybundle.Status, error) {
	store, err := policybundle.OpenStore(cfg.PolicyStateDir())
	if err != nil {
		return policybundle.Status{}, fmt.Errorf("open policy state: %w", err)
	}
	status, err := store.Status(time.Now().UTC())
	if err != nil {
		return status, errors.New("read policy state: " + err.Error())
	}
	return status, nil
}
