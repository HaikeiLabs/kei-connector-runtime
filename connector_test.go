package connectorruntime

import (
	"net/http"
	"net/http/httptest"
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
