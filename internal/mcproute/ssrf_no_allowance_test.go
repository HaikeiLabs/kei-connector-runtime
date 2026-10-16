package mcproute

import (
	"net"
	"net/url"
	"testing"
)

// TestSSRFNoAllowance: with no upstream allowance installed (AllowUpstream
// nil, as in every release build) the §4.10 guard refuses private and
// loopback upstreams at the URL check and at dial time.
func TestSSRFNoAllowance(t *testing.T) {
	prev := AllowUpstream
	AllowUpstream = nil
	t.Cleanup(func() { AllowUpstream = prev })
	for _, addr := range []string{"10.100.7.9", "127.0.0.1"} {
		if !isBlockedIP(net.ParseIP(addr)) {
			t.Errorf("isBlockedIP(%s) = false with no allowance", addr)
		}
		if err := defaultDialControl("tcp", net.JoinHostPort(addr, "443"), nil); err == nil {
			t.Errorf("dial control allowed %s with no allowance", addr)
		}
	}
	if err := checkSSRF(&url.URL{Scheme: "https", Host: "127.0.0.1"}); err == nil {
		t.Error("checkSSRF allowed a loopback upstream with no allowance")
	}
}
