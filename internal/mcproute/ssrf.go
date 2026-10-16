package mcproute

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
)

var errSSRFBlocked = errors.New("ssrf: address not allowed")

// AllowUpstream, when non-nil, reports whether an otherwise blocked upstream
// address may be dialed. It is set only by the e2e build's wiring, never in
// a release build; nil means the §4.10 guard applies unmodified.
var AllowUpstream func(netip.Addr) bool

// errEgressNotApproved is a dial to a host that no mcp descriptor in the
// bundle in force names (ADR-036 §4.10).
var errEgressNotApproved = fmt.Errorf("%w: destination is not an approved mcp host", errSSRFBlocked)

// blockedNets are ranges rejected by the dial Control hook in addition to
// loopback, private, link-local, unspecified and multicast addresses
// (ADR-036 §4.10 rule 2). IPv4-mapped forms match their IPv4 range.
var blockedNets = func() []*net.IPNet {
	cidrs := []string{
		"0.0.0.0/8",
		"100.64.0.0/10", // shared address space, including tailnet addresses
		"169.254.169.254/32",
		"192.0.0.0/24",
		"198.18.0.0/15",
		"240.0.0.0/4",
		"64:ff9b::/96",
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("mcproute: invalid blocked CIDR " + c + ": " + err.Error())
		}
		nets = append(nets, n)
	}
	return nets
}()

// isBlockedIP reports whether ip must not be dialed by the upstream client.
func isBlockedIP(ip net.IP) bool {
	// Only the e2e build's wiring sets AllowUpstream; a release build
	// leaves it nil, so the §4.10 guard applies unmodified.
	if AllowUpstream != nil {
		if addr, ok := netip.AddrFromSlice(ip); ok && AllowUpstream(addr.Unmap()) {
			return false
		}
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	for _, n := range blockedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// defaultDialControl is the net.Dialer Control hook for the upstream client.
// It sees the resolved IP actually being dialed, closing the DNS rebinding /
// TOCTOU gap left by the URL-level check.
func defaultDialControl(network, address string, c syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return errSSRFBlocked
	}
	ip := net.ParseIP(host)
	if ip == nil || isBlockedIP(ip) {
		return errSSRFBlocked
	}
	return nil
}

func checkSSRF(u *url.URL) error {
	if u.Scheme != "https" {
		return errSSRFBlocked
	}
	if u.User != nil {
		return errSSRFBlocked
	}
	host := u.Hostname()
	ips, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("dns resolution failed: %w", err)
	}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if isBlockedIP(ip) {
			return errSSRFBlocked
		}
	}
	return nil
}

// egressAllowed reports whether addr (host:port, as the transport dials it,
// before name resolution) is the host of an mcp descriptor URL in the bundle
// in force. Without a catalog nothing may be dialed.
func (h *Handler) egressAllowed(addr string) bool {
	if h.config.Catalog == nil {
		return false
	}
	for _, host := range h.config.Catalog.MCPHosts() {
		if strings.EqualFold(host, addr) {
			return true
		}
	}
	return false
}
