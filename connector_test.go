package connectorruntime

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// connector invoke applies the same fail-closed configuration check as
// authorize: a leftover legacy KEI_HARNESS_TOKEN stops the call before the
// control plane is contacted (ADR-020, HAI-219).
func TestConnectorInvokeRejectsLegacyHarnessToken(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer server.Close()
	t.Setenv("KEI_RUNTIME_TOKEN", "kh_live_runtime_token_1234567890")
	t.Setenv("KEI_RUNTIME_CONTROL_PLANE_URL", server.URL)
	t.Setenv("KEI_HARNESS_TOKEN", "kh_live_legacy_token_1234567890")
	code := runConnector([]string{"invoke", "--connector", "conn-1", "--capability", "lead.read", "--action", "read", "--resource", "leads"})
	if code != 1 || calls != 0 {
		t.Fatalf("exit = %d, catalog calls = %d; want 1 and 0", code, calls)
	}
}

// A connector call's execution record lands in the audit spool as a decision
// line the collector ships, with the input digest and no input.
func TestConnectorInvokeWritesAShippableAuditRecord(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"decision":"deny","reason":"no matching policy"}`))
	}))
	defer server.Close()
	spool := filepath.Join(t.TempDir(), "audit.jsonl")
	t.Setenv("KEI_RUNTIME_TOKEN", "kh_live_runtime_token_1234567890")
	t.Setenv("KEI_RUNTIME_CONTROL_PLANE_URL", server.URL)
	t.Setenv("KEI_PROXY_AUDIT", spool)
	code := runConnector([]string{"invoke", "--connector", "conn-1", "--capability", "message.search", "--action", "read",
		"--resource", "gmail/messages", "--trace-id", "trace-audit-1", "--input", `{"query":"from:alice"}`})
	if code != 1 {
		t.Fatalf("exit = %d, want 1 for a deny", code)
	}
	data, err := os.ReadFile(spool)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 || strings.Contains(lines[0], "from:alice") {
		t.Fatalf("spool = %q", data)
	}
	event, ok := parseAuditLine(lines[0])
	if !ok || event.Decision != "deny" || event.ParentSpan == nil || *event.ParentSpan != "trace-audit-1" ||
		event.ToolArgsDigest == nil || !strings.HasPrefix(*event.ToolArgsDigest, "sha256:") || event.ToolName != "connector:message.search" {
		t.Fatalf("parsed event = %+v, ok %v", event, ok)
	}
}
