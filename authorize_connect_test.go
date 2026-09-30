package connectorruntime

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

// TestAuthorizeConnectPassThrough: when the catalog returns
// oauth_not_connected with a connect object, the proxy output must
// include the opaque connect field and exit 1 (deny).
func TestAuthorizeConnectPassThrough(t *testing.T) {
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

	connectJSON := json.RawMessage(`{"url":"https://example.kei.test/connect/gmail#claim=abc123","provider":"gmail","connector_id":"conn-1","expires_at":"2026-10-01T00:00:00Z","reason":"oauth_not_connected"}`)

	policyCatalog := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/authorize":
			mu.Lock()
			defer mu.Unlock()
			authorizeBody = map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&authorizeBody)
			json.NewEncoder(w).Encode(AuthorizeResponse{
				Decision: "enrollment_required",
				Reason:   "no gmail connection for this user",
				Connect:  &connectJSON,
			})
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

	var exitCode int
	stdout := captureStdout(func() {
		exitCode = runAuthorize([]string{
			"--tool", "gmail.search",
			"--action", "gmail:read",
			"--resource", "acme/inbox",
		})
	})

	if exitCode != 1 {
		t.Fatalf("expected exit code 1 (deny), got %d", exitCode)
	}

	var out AuthorizeOutput
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &out); err != nil {
		t.Fatalf("unmarshal stdout: %v\nstdout: %s", err, stdout)
	}
	if out.Decision != "deny" {
		t.Fatalf("decision = %q, want deny", out.Decision)
	}
	if out.Connect == nil {
		t.Fatal("connect field must be present on enrollment_required decision with connect")
	}
	var connect map[string]any
	if err := json.Unmarshal(*out.Connect, &connect); err != nil {
		t.Fatalf("unmarshal connect: %v", err)
	}
	if url, ok := connect["url"].(string); !ok || url != "https://example.kei.test/connect/gmail#claim=abc123" {
		t.Fatalf(`connect.url = %v, want "https://example.kei.test/connect/gmail#claim=abc123"`, connect["url"])
	}
	if provider, ok := connect["provider"].(string); !ok || provider != "gmail" {
		t.Fatalf(`connect.provider = %v, want "gmail"`, connect["provider"])
	}

	mu.Lock()
	defer mu.Unlock()
	if authorizeBody == nil {
		t.Fatal("authorize request was never sent")
	}
}

// TestAuthorizeConnectOnDefaultDeny: when the catalog returns a plain deny
// with a connect object (e.g. oauth_reconnect_required), the proxy output
// must include the connect field and exit 1.
func TestAuthorizeConnectOnDefaultDeny(t *testing.T) {
	workspaceKey := "workspace-key"

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

	connectJSON := json.RawMessage(`{"url":"https://example.kei.test/connect/gmail#claim=def456","provider":"gmail","connector_id":"conn-1","expires_at":"2026-10-01T00:00:00Z","reason":"oauth_reconnect_required"}`)

	policyCatalog := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/authorize":
			json.NewEncoder(w).Encode(AuthorizeResponse{
				Decision: "deny",
				Reason:   "oauth reconnection required",
				Connect:  &connectJSON,
			})
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

	var exitCode int
	stdout := captureStdout(func() {
		exitCode = runAuthorize([]string{
			"--tool", "gmail.search",
			"--action", "gmail:read",
			"--resource", "acme/inbox",
		})
	})

	if exitCode != 1 {
		t.Fatalf("expected exit code 1 (deny), got %d", exitCode)
	}

	var out AuthorizeOutput
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &out); err != nil {
		t.Fatalf("unmarshal stdout: %v\nstdout: %s", err, stdout)
	}
	if out.Decision != "deny" {
		t.Fatalf("decision = %q, want deny", out.Decision)
	}
	if out.Connect == nil {
		t.Fatal("connect field must be present on deny with connect")
	}
	var connect map[string]any
	if err := json.Unmarshal(*out.Connect, &connect); err != nil {
		t.Fatalf("unmarshal connect: %v", err)
	}
	if reason, ok := connect["reason"].(string); !ok || reason != "oauth_reconnect_required" {
		t.Fatalf(`connect.reason = %v, want "oauth_reconnect_required"`, connect["reason"])
	}
}

// TestAuthorizePlainDenyHasNoConnect: a regular deny from the catalog must
// not include a connect field in the output.
func TestAuthorizePlainDenyHasNoConnect(t *testing.T) {
	workspaceKey := "workspace-key"

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
			json.NewEncoder(w).Encode(AuthorizeResponse{
				Decision: "deny",
				Reason:   "policy violation",
			})
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

	var exitCode int
	stdout := captureStdout(func() {
		exitCode = runAuthorize([]string{
			"--tool", "github.create_pr",
			"--action", "github:write",
			"--resource", "acme/widgets",
		})
	})

	if exitCode != 1 {
		t.Fatalf("expected exit code 1 (deny), got %d", exitCode)
	}

	var out AuthorizeOutput
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &out); err != nil {
		t.Fatalf("unmarshal stdout: %v\nstdout: %s", err, stdout)
	}
	if out.Decision != "deny" {
		t.Fatalf("decision = %q, want deny", out.Decision)
	}
	if out.Connect != nil {
		t.Fatal("connect field must be absent on plain deny")
	}
}

// TestAuthorizeConnectURLNotLoggedAtInfo verifies the connect URL does
// not appear in stderr (info-level logs). We capture stderr while running
// authorize with an enrollment_required response that includes connect
// and check the URL is absent in stderr.
func TestAuthorizeConnectURLNotLoggedAtInfo(t *testing.T) {
	workspaceKey := "workspace-key"

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

	connectJSON := json.RawMessage(`{"url":"https://sensitive-connect.test/oauth/start#claim=secret-claim","provider":"gmail","connector_id":"conn-1","expires_at":"2026-10-01T00:00:00Z","reason":"oauth_not_connected"}`)

	policyCatalog := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/authorize":
			json.NewEncoder(w).Encode(AuthorizeResponse{
				Decision: "enrollment_required",
				Reason:   "no gmail connection for this user",
				Connect:  &connectJSON,
			})
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

	// Capture stderr to check for the URL in logs
	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	exitCode := runAuthorize([]string{
		"--tool", "gmail.search",
		"--action", "gmail:read",
		"--resource", "acme/inbox",
	})

	w.Close()
	os.Stderr = origStderr
	var stderrBuf bytes.Buffer
	io.Copy(&stderrBuf, r)
	stderr := stderrBuf.String()

	if exitCode != 1 {
		t.Fatalf("expected exit code 1 (deny), got %d", exitCode)
	}

	// The connect URL must not appear in stderr logs. The URL contains
	// a sensitive claim secret and should never be written to logs.
	if strings.Contains(stderr, "sensitive-connect.test") {
		t.Error("connect URL leaked into stderr logs")
	}
	if strings.Contains(stderr, "secret-claim") {
		t.Error("connect claim secret leaked into stderr logs")
	}
}
