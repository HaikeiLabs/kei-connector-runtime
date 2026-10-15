//go:build e2e

package connectorruntime

import (
	"testing"

	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/mcproute"
)

// TestE2EWiringInstallsAllowance builds the mcp route through the serve
// wiring and asserts the e2e allowance is installed on the §4.10 guard. It
// fails if the install line in e2e_wiring.go is removed.
func TestE2EWiringInstallsAllowance(t *testing.T) {
	cfg := Config{RuntimeToken: "kh_live_runtime_test_token_1234567890", RuntimeStateDir: t.TempDir()}
	local := keiruntime.NewLocalPDP(cfg, nil)
	t.Cleanup(local.Close)
	newMCPRoute(cfg, local)
	if mcproute.AllowUpstream == nil {
		t.Fatal("the e2e wiring did not install mcproute.AllowUpstream")
	}
}
