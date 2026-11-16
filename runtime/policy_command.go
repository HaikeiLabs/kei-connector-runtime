package runtime

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/harnessresync"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

// RunPolicySync fetches the installation's bundle once over HTTPS with the
// runtime token, validates it against kei.policy-bundle/v2 and persists it
// atomically (0600) in KEI_RUNTIME_STATE_DIR, then prints `policy show`.
func RunPolicySync(ctx context.Context, args []string, stdout, stderr io.Writer, cfg PolicyConfig, identityFunc IdentityFunc, syncBundle SyncBundleFunc, checkRevocation func(error) bool, revokeState func(), forceSyncBundle ...SyncBundleFunc) int {
	fs := flag.NewFlagSet("policy sync", flag.ContinueOnError)
	fs.SetOutput(stderr)
	force := fs.Bool("force", false, "request a fresh policy bundle from the catalog")
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
	var syncErr error
	if *force {
		if len(forceSyncBundle) == 0 || forceSyncBundle[0] == nil {
			fmt.Fprintln(stderr, "Error: forced policy refresh is unavailable")
			return 1
		}
		syncErr = forceSyncBundle[0](identity)
	} else {
		syncErr = syncBundle(identity)
	}
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
	show := policyShow{Status: status}
	if resync, err := harnessresync.LoadStatus(cfg.PolicyStateDir()); err == nil {
		show.HarnessResync = resync
	}
	if err := WriteJSON(stdout, show); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if status.State != policybundle.Active && status.State != policybundle.Stale {
		return 1
	}
	return 0
}

// policyShow is `policy show` output: the bundle status plus, on a desktop
// install, the harness resync state ("harness resync backoff" when a harness
// keeps getting rewritten).
type policyShow struct {
	policybundle.Status
	HarnessResync *harnessresync.Status `json:"harness_resync,omitempty"`
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
