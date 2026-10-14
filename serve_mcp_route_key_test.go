package connectorruntime

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/invoke"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/credentials"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/mcproute"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
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

const (
	mcpConnectorID = "conn-mcp-1"
	mcpTokenCanary = "kei-canary-mcp-connector-token-577"
)

// TestMCPRoute_ResolvesTheSessionsConnectorCredential builds the route
// through the serve wiring: its credential source releases the linked
// session's token for one connector and resource through the HAI-577
// connector-scoped resolve, and maps a failure to a CredentialDenied.
func TestMCPRoute_ResolvesTheSessionsConnectorCredential(t *testing.T) {
	rig := newInvokeRigConfig(t, func(c *Config) { c.MCPListenAddr = defaultMCPListenAddr })
	id := rig.startNamedSession(t)
	sub, ok := rig.local.Sessions.Get(id)
	if !ok {
		t.Fatal("no session")
	}
	sess := &mcproute.Session{Subject: sub.UserID, SessionID: id, Agent: "agent-fixture-0001"}
	if rig.mcp.credentials == nil {
		t.Fatal("the route has no credential source")
	}

	var got mcproute.ConnectorCredential
	if err := rig.mcp.credentials.UseCredential(context.Background(), sess, mcpConnectorID, "https://mcp.example/mcp", func(c mcproute.ConnectorCredential) error {
		got = c
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != mcpTokenCanary || got.ConnectorID != mcpConnectorID || got.Resource != "https://mcp.example/mcp" || got.Issuer != "https://auth.mcp.example" {
		t.Fatalf("credential = connector %q resource %q issuer %q (token matches: %v)", got.ConnectorID, got.Resource, got.Issuer, got.AccessToken == mcpTokenCanary)
	}

	err := rig.mcp.credentials.UseCredential(context.Background(), sess, "conn-other", "https://mcp.example/mcp", func(mcproute.ConnectorCredential) error { return nil })
	var denied *mcproute.CredentialDenied
	if !errors.As(err, &denied) || denied.Reason != "NOT_CONNECTED" {
		t.Fatalf("unconnected connector: err = %v, want CredentialDenied NOT_CONNECTED", err)
	}
	other := &mcproute.Session{Subject: "someone-else", SessionID: id}
	if err := rig.mcp.credentials.UseCredential(context.Background(), other, mcpConnectorID, "https://mcp.example/mcp", func(mcproute.ConnectorCredential) error { return nil }); !errors.As(err, &denied) {
		t.Fatalf("another subject: err = %v, want a denial", err)
	}
}

type memorySecretStore map[string]string

func (m memorySecretStore) Get(_ context.Context, backend, ref string) (*string, error) {
	v, ok := m[backend+"|"+ref]
	if !ok {
		return nil, errors.New("no such secret")
	}
	return &v, nil
}

// TestMCPSecretFields_ResolveEachFieldFromTheConnectorIndex: the serve
// adapter resolves kei://connectors/<id>/<field> through the connector
// reference index and the tenant secret store, as for opaque_ref connectors.
func TestMCPSecretFields_ResolveEachFieldFromTheConnectorIndex(t *testing.T) {
	stateDir := t.TempDir()
	index := credentials.ConnectorIndexPath(stateDir)
	ref := "aws-secrets-manager://us-west-2/kei/acme/connectors/00000000-0000-4000-8000-000000000581/app_key"
	if err := credentials.WriteConnectorReference(index, credentials.ConnectorReference{ConnectorID: "00000000-0000-4000-8000-000000000581", Field: "app_key", SecretBackend: "aws-secrets-manager", SecretRef: ref, Generation: 1}); err != nil {
		t.Fatal(err)
	}
	s := mcpSecretFields{resolver: invoke.SecretResolver{IndexPath: index, Store: memorySecretStore{"aws-secrets-manager|" + ref: "app-key-value"}}}
	d := policybundle.Connector{ID: "00000000-0000-4000-8000-000000000581", CredentialSource: "opaque_ref", CredentialRef: "kei://connectors/00000000-0000-4000-8000-000000000581/api_key", CredentialBackend: "aws-secrets-manager"}

	if v, err := s.Resolve(context.Background(), d, "app_key"); err != nil || v != "app-key-value" {
		t.Fatalf("app_key = %q, %v", v, err)
	}
	if _, err := s.Resolve(context.Background(), d, "api_key"); err == nil {
		t.Fatal("an undelivered field resolved")
	}
	other := d
	other.CredentialBackend = "azure-key-vault"
	if _, err := s.Resolve(context.Background(), other, "app_key"); err == nil {
		t.Fatal("a field resolved from another backend than the descriptor names")
	}
}

// TestMCPRoute_WiresSecretFieldsToTheConnectorIndex builds the route
// through the serve wiring: its secret source reads the state directory's
// connector reference index.
func TestMCPRoute_WiresSecretFieldsToTheConnectorIndex(t *testing.T) {
	cfg := Config{RuntimeToken: "kh_live_runtime_test_token_1234567890", RuntimeStateDir: t.TempDir()}
	local := keiruntime.NewLocalPDP(cfg, nil)
	t.Cleanup(local.Close)
	route := newMCPRoute(cfg, local)
	s, ok := route.secrets.(mcpSecretFields)
	if !ok || s.resolver.IndexPath != credentials.ConnectorIndexPath(cfg.RuntimeStateDir) {
		t.Fatalf("route secrets = %#v, want the connector index of the state dir", route.secrets)
	}
}
