//go:build e2e

package e2e

import (
	"testing"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/mcproute"
)

func TestE2EAllowanceParse(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		want      int // number of prefixes kept; 0 means nothing is allowed
	}{
		{"empty", "", 0},
		{"one service ip", "172.20.14.3/32", 1},
		{"loopback and a pod range", "127.0.0.1/32, 10.100.0.0/16", 2},
		{"cgnat", "100.64.12.0/24", 1},
		{"ipv6 loopback", "::1/128", 1},
		{"too broad ipv4", "10.0.0.0/8", 0},
		{"too broad ipv6", "fd00::/48", 0},
		{"public range", "8.8.8.0/24", 0},
		{"metadata", "169.254.169.254/32", 0},
		{"unspecified", "0.0.0.0/32", 0},
		{"host bits set", "10.100.0.1/16", 0},
		{"not a prefix", "10.100.0.1", 0},
		// One bad entry voids the whole list: fail closed.
		{"one bad entry", "172.20.14.3/32,169.254.169.254/32", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := len(parseE2EAllowance(tc.raw)); got != tc.want {
				t.Fatalf("parseE2EAllowance(%q) kept %d prefixes, want %d", tc.raw, got, tc.want)
			}
		})
	}
}

// TestInstallSetsHook: Install wires the allowance into mcproute.
func TestInstallSetsHook(t *testing.T) {
	t.Setenv("KEI_PROXY_E2E_ALLOW_CIDRS", "172.20.14.3/32")
	resetE2EAllowanceForTest()
	t.Cleanup(resetE2EAllowanceForTest)
	prev := mcproute.AllowUpstream
	t.Cleanup(func() { mcproute.AllowUpstream = prev })
	Install()
	if mcproute.AllowUpstream == nil {
		t.Fatal("Install did not set mcproute.AllowUpstream")
	}
}
