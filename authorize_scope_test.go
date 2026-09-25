package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestResolveRuntimeScopeHappyPath(t *testing.T) {
	workspaceKey := "workspace-9"
	identity := &RuntimeIdentity{ID: "installation-1", OrgID: "org-1", WorkspaceID: &workspaceKey}

	orgID, workspaceID, err := resolveRuntimeScope(identity)
	if err != nil {
		t.Fatal(err)
	}
	if orgID != "org-1" {
		t.Fatalf("org_id = %q, want org-1", orgID)
	}
	if workspaceID != "workspace-9" {
		t.Fatalf("workspace_id = %q, want workspace-9", workspaceID)
	}
}

func TestResolveRuntimeScopeNilWorkspaceFailsHard(t *testing.T) {
	identity := &RuntimeIdentity{ID: "installation-1", OrgID: "org-1"}

	_, _, err := resolveRuntimeScope(identity)
	if err == nil {
		t.Fatal("expected nil workspace to fail hard")
	}
	for _, want := range []string{"installation-1", "no workspace", "re-minted"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err.Error(), want)
		}
	}
}

func TestResolveRuntimeScopeMissingIdentityFails(t *testing.T) {
	if _, _, err := resolveRuntimeScope(nil); err == nil {
		t.Fatal("expected missing identity to fail")
	}
}

func TestRunAuthorizeWhoAmIFailureIsFatal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	t.Setenv("KEI_RUNTIME_TOKEN", "kh_live_runtime_test_token_1234567890")
	t.Setenv("KEI_RUNTIME_CONTROL_PLANE_URL", server.URL)
	t.Setenv("KEI_PROXY_REGISTRY", "tools.yaml")

	if code := runAuthorize([]string{"--tool", "github.create_pr", "--action", "github:write", "--resource", "acme/widgets"}); code == 0 {
		t.Fatal("expected whoami failure to be fatal")
	}
}

func TestRunAuthorizeHappyPathDerivesWorkspaceFromKey(t *testing.T) {
	workspaceKey := "workspace-key"
	var mu sync.Mutex
	var authorizeBody map[string]any

	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/runtime/whoami":
			json.NewEncoder(w).Encode(RuntimeIdentity{
				ID: "installation-1", OrgID: "org-1", WorkspaceID: &workspaceKey,
				Platform: "discord", Status: "active", BindingStatus: "verified",
			})
		case "/api/v1/runtime/heartbeat":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer controlPlane.Close()

	policyCatalog := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/authorize":
			mu.Lock()
			defer mu.Unlock()
			authorizeBody = map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&authorizeBody)
			json.NewEncoder(w).Encode(AuthorizeResponse{Decision: "deny", Reason: "policy"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer policyCatalog.Close()

	t.Setenv("KEI_RUNTIME_TOKEN", "kh_live_runtime_test_token_1234567890")
	t.Setenv("KEI_RUNTIME_CONTROL_PLANE_URL", controlPlane.URL)
	t.Setenv("KEI_API_URL", policyCatalog.URL)
	t.Setenv("ABAC_URL", "")
	t.Setenv("KEI_PROXY_REGISTRY", "tools.yaml")

	code := runAuthorize([]string{
		"--tool", "github.create_pr",
		"--action", "github:write",
		"--resource", "acme/widgets",
	})
	if code == 0 {
		t.Fatal("expected deny to exit non-zero")
	}

	mu.Lock()
	defer mu.Unlock()
	if authorizeBody == nil {
		t.Fatal("authorize request was never sent")
	}
	if got, ok := authorizeBody["workspace_id"].(string); !ok || got != workspaceKey {
		t.Fatalf("authorize request workspace_id = %v, want key value %q", authorizeBody["workspace_id"], workspaceKey)
	}
}

func TestRunAuthorizeNilWorkspaceIsFatal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/runtime/whoami":
			json.NewEncoder(w).Encode(RuntimeIdentity{
				ID: "installation-1", OrgID: "org-1",
				Platform: "discord", Status: "active", BindingStatus: "verified",
			})
		case "/api/v1/runtime/heartbeat":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	t.Setenv("KEI_RUNTIME_TOKEN", "kh_live_runtime_test_token_1234567890")
	t.Setenv("KEI_RUNTIME_CONTROL_PLANE_URL", server.URL)
	t.Setenv("KEI_PROXY_REGISTRY", "tools.yaml")

	if code := runAuthorize([]string{"--tool", "github.create_pr", "--action", "github:write", "--resource", "acme/widgets"}); code == 0 {
		t.Fatal("expected nil workspace to be fatal")
	}
}
