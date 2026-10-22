package connectorruntime

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthorizeColdRuntimeDeniesWithoutCatalogDecision(t *testing.T) {
	workspace := "ws-fixture-0001"
	var authorizeCalls int
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/runtime/whoami":
			_ = json.NewEncoder(w).Encode(RuntimeIdentity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: &workspace, Platform: "discord", Status: "active", BindingStatus: "verified"})
		case "/api/v1/runtime:heartbeat":
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/authorize":
			authorizeCalls++
			http.Error(w, "legacy decision endpoint must not be called", 500)
		default:
			http.NotFound(w, r)
		}
	}))
	defer control.Close()
	t.Setenv("KEI_RUNTIME_TOKEN", "kh_live_runtime_test_token_1234567890")
	t.Setenv("KEI_RUNTIME_CONTROL_PLANE_URL", control.URL)
	t.Setenv("KEI_RUNTIME_STATE_DIR", t.TempDir())
	var code int
	stdout := captureStdout(func() { code = runAuthorize([]string{"--tool", "web_search", "--action", "tool:web_search"}) })
	if code != 1 {
		t.Fatalf("exit=%d stdout=%s", code, stdout)
	}
	var out AuthorizeOutput
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &out); err != nil {
		t.Fatalf("decode output %v: %s", err, stdout)
	}
	if out.Decision != "deny" || out.ReasonCode != "policy_bundle_missing" || out.DenySource != "runtime_state" {
		t.Fatalf("cold decision=%+v", out)
	}
	if authorizeCalls != 0 {
		t.Fatalf("per-call catalog /authorize calls=%d", authorizeCalls)
	}
}
