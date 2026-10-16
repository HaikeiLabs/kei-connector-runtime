//go:build e2e

// The private upstream allowance exists only in binaries built with the e2e
// tag (kei ADR-036 §10, HAI-488 test 19). It lets the connector e2e reach its
// test MCP server on a cluster address, which the §4.10 guard otherwise
// refuses. Release builds never import this package, so they cannot enable
// it: mcproute.AllowUpstream stays nil and the guard applies unmodified.

package e2e

import (
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/mcproute"
)

// Install sets mcproute.AllowUpstream to the e2e allowance and logs a
// warning naming the allowance in force. The e2e build's wiring calls it
// once at startup; release builds never import this package.
func Install() {
	mcproute.AllowUpstream = func(addr netip.Addr) bool { return e2eAllowedIP(addr.AsSlice()) }
	announceE2EAllowance(slog.Default())
}

// e2eAllowanceEnv lists the prefixes, comma-separated, an e2e build may dial.
const e2eAllowanceEnv = "KEI_PROXY_E2E_ALLOW_CIDRS"

// e2eAllowanceParents are the only ranges an allowance prefix may fall in:
// loopback, private and shared (CGNAT) space, where a test cluster's pods
// and services live. Link-local, metadata and public space never qualify.
var e2eAllowanceParents = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
}

var (
	e2eAllowanceOnce     sync.Once
	e2eAllowancePrefixes []netip.Prefix
)

// parseE2EAllowance returns the prefixes in raw, or nil if any entry is not
// a masked prefix of at least /16 (IPv4) or /64 (IPv6) inside one of
// e2eAllowanceParents. One bad entry voids the list, so a typo fails closed.
func parseE2EAllowance(raw string) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(entry)
		if err != nil || prefix != prefix.Masked() {
			return nil
		}
		minBits := 16
		if prefix.Addr().Is6() {
			minBits = 64
		}
		if prefix.Bits() < minBits || !withinE2EAllowanceParents(prefix) {
			return nil
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

func withinE2EAllowanceParents(prefix netip.Prefix) bool {
	for _, parent := range e2eAllowanceParents {
		if parent.Bits() <= prefix.Bits() && parent.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

func e2eAllowance() []netip.Prefix {
	e2eAllowanceOnce.Do(func() {
		e2eAllowancePrefixes = parseE2EAllowance(os.Getenv(e2eAllowanceEnv))
	})
	return e2eAllowancePrefixes
}

// resetE2EAllowanceForTest makes the next lookup read the variable again.
func resetE2EAllowanceForTest() {
	e2eAllowanceOnce = sync.Once{}
	e2eAllowancePrefixes = nil
}

// e2eAllowedIP reports whether ip is in the e2e allowance.
func e2eAllowedIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range e2eAllowance() {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// announceE2EAllowance warns that this is an e2e build, and names the
// allowance in force, so it is never mistaken for a release.
func announceE2EAllowance(logger *slog.Logger) {
	prefixes := e2eAllowance()
	names := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		names[i] = prefix.String()
	}
	logger.Warn("e2e build: the mcp route may dial these private upstreams", "allowance", strings.Join(names, ","))
}
