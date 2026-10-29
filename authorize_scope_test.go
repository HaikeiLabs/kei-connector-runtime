package connectorruntime

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveRuntimeScopeMissingIdentityFails(t *testing.T) {
	if _, _, err := resolveRuntimeScope(nil); err == nil {
		t.Fatal("expected missing identity to fail")
	}
}
func TestRunAuthorizeWhoAmIFailureIsFatal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	defer server.Close()
	t.Setenv("KEI_RUNTIME_TOKEN", "kh_live_runtime_test_token_1234567890")
	t.Setenv("KEI_RUNTIME_CONTROL_PLANE_URL", server.URL)
	t.Setenv("KEI_RUNTIME_STATE_DIR", t.TempDir())
	if code := runAuthorize([]string{"--tool", "github.create_pr", "--action", "github:write", "--resource", "acme/widgets"}); code != 2 {
		t.Fatalf("whoami failure exit = %d, want 2 (error)", code)
	}
}
func TestRunAuthorizeNeverCallsCatalogDecisionEndpoint(t *testing.T) {
	workspace := "ws-1"
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/runtime/whoami":
			_ = json.NewEncoder(w).Encode(RuntimeIdentity{ID: "installation-1", OrgID: "org-1", WorkspaceID: &workspace, Platform: "discord", Status: "active", BindingStatus: "verified"})
		case "/api/v1/runtime:heartbeat":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer control.Close()
	called := false
	catalog := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/authorize" {
			called = true
		}
		http.NotFound(w, r)
	}))
	defer catalog.Close()
	t.Setenv("KEI_RUNTIME_TOKEN", "kh_live_runtime_test_token_1234567890")
	t.Setenv("KEI_RUNTIME_CONTROL_PLANE_URL", control.URL)
	t.Setenv("KEI_API_URL", catalog.URL)
	t.Setenv("KEI_RUNTIME_STATE_DIR", t.TempDir())
	out := captureStdout(func() {
		if code := runAuthorize([]string{"--tool", "github.create_pr", "--action", "github:write", "--resource", "acme/widgets"}); code != 1 {
			t.Fatalf("cold runtime exit = %d, want 1 (deny)", code)
		}
	})
	var result AuthorizeOutput
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("decode output: %v (%s)", err, out)
	}
	if result.ReasonCode != "policy_bundle_missing" {
		t.Fatalf("reason_code=%q", result.ReasonCode)
	}
	if called {
		t.Fatal("per-call /authorize called")
	}
}
func TestRunAuthorizeNilWorkspaceIsFatal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/runtime/whoami":
			_ = json.NewEncoder(w).Encode(RuntimeIdentity{ID: "installation-1", OrgID: "org-1", Platform: "discord", Status: "active", BindingStatus: "verified"})
		case "/api/v1/runtime:heartbeat":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	t.Setenv("KEI_RUNTIME_TOKEN", "kh_live_runtime_test_token_1234567890")
	t.Setenv("KEI_RUNTIME_CONTROL_PLANE_URL", server.URL)
	t.Setenv("KEI_RUNTIME_STATE_DIR", t.TempDir())
	if code := runAuthorize([]string{"--tool", "github.create_pr", "--action", "github:write", "--resource", "acme/widgets"}); code == 0 {
		t.Fatal("expected nil workspace to be fatal")
	}
}
