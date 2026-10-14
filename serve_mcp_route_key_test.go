package connectorruntime

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// HAI-488 (ADR-036 §4.4): `kei-proxy run --harness-kind <kind> -- <harness>`
// in a named session gives the harness a route key in KEI_MCP_ROUTE_KEY,
// through the real serve wiring. The child uses it against the route; the key
// never appears in the relayed output, and it is revoked when the child
// exits. No connector credential reaches the child.
func TestCommandRunGivesTheHarnessAWorkingRouteKey(t *testing.T) {
	rig := newInvokeRigConfig(t, func(c *Config) { c.MCPListenAddr = defaultMCPListenAddr })
	id := rig.startNamedSession(t)
	route := httptest.NewServer(rig.mcp.handler)
	t.Cleanup(route.Close)
	keyFile := filepath.Join(t.TempDir(), "route-key")

	code, stdout, stderr := runProxyRunCLI(t, rig.socket, map[string]string{
		"KEI_SESSION_ID":          id,
		"KEI_MCP_ROUTE_KEY":       "kmr_spoofed",
		"KEI_RUN_HELPER_MCP_URL":  route.URL + "/mcp/any_slug",
		"KEI_RUN_HELPER_KEY_FILE": keyFile,
		"KEI_RUN_HELPER_EXIT":     "0",
	}, "--harness-kind", "claude_code", "--", helperBinary(t))

	if code != 0 {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "mcp-ping=200") {
		t.Fatalf("the child could not use its route key:\n%s", stdout)
	}
	if !strings.Contains(stdout, "route-key=[REDACTED]") {
		t.Fatalf("route key not redacted:\n%s", stdout)
	}
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	key := string(raw)
	if !strings.HasPrefix(key, "kmr_") || key == "kmr_spoofed" || len(key) != 47 {
		t.Fatalf("child key %q is not a minted kmr_ key", key)
	}
	if _, ok := rig.mcp.keys.Validate(key); ok {
		t.Fatal("the route key still validates after the child exited")
	}
	if strings.Contains(stdout, "token-sha256="+credentialCanaryDigest) || strings.Contains(stdout, "GH_TOKEN") {
		t.Fatalf("a connector credential reached the harness environment:\n%s", stdout)
	}
	spool := readSpool(t, rig.cfg.AuditPath)
	for name, text := range map[string]string{"stdout": stdout, "stderr": stderr, "audit spool": spool} {
		if strings.Contains(text, key) || strings.Contains(text, credentialCanary) {
			t.Fatalf("%s carries the route key or a credential:\n%s", name, text)
		}
	}
}

func TestCommandRunRouteKeyNeedsALiveNamedSession(t *testing.T) {
	rig := newInvokeRigConfig(t, func(c *Config) { c.MCPListenAddr = defaultMCPListenAddr })
	rig.startNamedSession(t)

	code, stdout, stderr := runProxyRunCLI(t, rig.socket, map[string]string{"KEI_SESSION_ID": "ks_not_a_live_session", "KEI_RUN_HELPER_EXIT": "0"}, "--harness-kind", "claude_code", "--", helperBinary(t))

	if code != 1 || !strings.Contains(stderr, "session_not_found") || strings.Contains(stdout, "env-keys") {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
}
