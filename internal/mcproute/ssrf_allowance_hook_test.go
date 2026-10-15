package mcproute

import (
	"net"
	"net/netip"
	"net/url"
	"testing"
)

// TestSSRFAllowanceHook: with an upstream allowance installed (as the e2e
// build's wiring does), the listed address passes the §4.10 guard while every
// other private address stays refused.
func TestSSRFAllowanceHook(t *testing.T) {
	allowed := netip.MustParsePrefix("172.20.14.3/32")
	prev := AllowUpstream
	AllowUpstream = func(addr netip.Addr) bool { return allowed.Contains(addr) }
	t.Cleanup(func() { AllowUpstream = prev })

	for _, addr := range []string{"172.20.14.3", "::ffff:172.20.14.3"} {
		if isBlockedIP(net.ParseIP(addr)) {
			t.Errorf("isBlockedIP(%s) = true, want allowed", addr)
		}
		if err := defaultDialControl("tcp", net.JoinHostPort(addr, "443"), nil); err != nil {
			t.Errorf("dial control refused %s: %v", addr, err)
		}
	}
	for _, addr := range []string{"172.20.14.4", "127.0.0.1", "10.0.0.1", "169.254.169.254"} {
		if !isBlockedIP(net.ParseIP(addr)) {
			t.Errorf("isBlockedIP(%s) = false, want blocked", addr)
		}
	}
	if err := checkSSRF(&url.URL{Scheme: "https", Host: "172.20.14.3"}); err != nil {
		t.Errorf("checkSSRF refused an allowed upstream: %v", err)
	}
	// The allowance never relaxes the scheme rule.
	if err := checkSSRF(&url.URL{Scheme: "http", Host: "172.20.14.3"}); err == nil {
		t.Error("checkSSRF allowed http")
	}
	if err := checkSSRF(&url.URL{Scheme: "https", Host: "127.0.0.1"}); err == nil {
		t.Error("checkSSRF allowed a non-allowed loopback upstream")
	}
}
