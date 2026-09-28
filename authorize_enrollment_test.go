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

// captureStdout runs f and returns everything written to os.Stdout during f.
func captureStdout(f func()) string {
	orig := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	f()
	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

// TestAuthorizeEnrollmentPassThrough: when the catalog returns
// enrollment_required with an enrollment object, the proxy output must
// include the opaque enrollment field and exit 1 (deny).
func TestAuthorizeEnrollmentPassThrough(t *testing.T) {
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

	enrollmentJSON := json.RawMessage(`{"url":"https://example.kei.test/identity/link#claim=abc123","provider":"discord","provider_user_id":"user-1","org_id":"org-1","workspace_id":"ws-1"}`)

	policyCatalog := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/authorize":
			mu.Lock()
			defer mu.Unlock()
			authorizeBody = map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&authorizeBody)
			json.NewEncoder(w).Encode(AuthorizeResponse{
				Decision:   "enrollment_required",
				Reason:     "identity not linked",
				Enrollment: &enrollmentJSON,
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
	if out.Enrollment == nil {
		t.Fatal("enrollment field must be present on enrollment_required decision")
	}
	var enrollment map[string]any
	if err := json.Unmarshal(*out.Enrollment, &enrollment); err != nil {
		t.Fatalf("unmarshal enrollment: %v", err)
	}
	if url, ok := enrollment["url"].(string); !ok || url != "https://example.kei.test/identity/link#claim=abc123" {
		t.Fatalf("enrollment.url = %v, want https://example.kei.test/identity/link#claim=abc123", enrollment["url"])
	}

	mu.Lock()
	defer mu.Unlock()
	if authorizeBody == nil {
		t.Fatal("authorize request was never sent")
	}
}

// TestAuthorizePlainDenyHasNoEnrollment: a regular deny from the catalog must
// not include an enrollment field in the output.
func TestAuthorizePlainDenyHasNoEnrollment(t *testing.T) {
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
	if out.Enrollment != nil {
		t.Fatal("enrollment field must be absent on plain deny")
	}
}

// TestAuthorizeEnrollmentRequiredNoEnrollmentObject: if the catalog returns
// enrollment_required without an enrollment object, the proxy must still
// deny and not inject an enrollment field.
func TestAuthorizeEnrollmentRequiredNoEnrollmentObject(t *testing.T) {
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
				Decision: "enrollment_required",
				Reason:   "identity not linked",
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
	if out.Enrollment != nil {
		t.Fatal("enrollment must be nil when catalog returns enrollment_required without an enrollment object")
	}
}

// TestAuthorizeEnrollmentURLNotLoggedAtInfo verifies the enrollment URL does
// not appear in stderr (info-level logs). We capture stderr while running
// authorize with an enrollment_required response and check the URL is absent.
func TestAuthorizeEnrollmentURLNotLoggedAtInfo(t *testing.T) {
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

	enrollmentJSON := json.RawMessage(`{"url":"https://sensitive-enroll.test/identity/link#claim=secret-token","provider":"discord","provider_user_id":"user-1","org_id":"org-1","workspace_id":"ws-1"}`)

	policyCatalog := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/authorize":
			json.NewEncoder(w).Encode(AuthorizeResponse{
				Decision:   "enrollment_required",
				Reason:     "identity not linked",
				Enrollment: &enrollmentJSON,
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
		"--tool", "github.create_pr",
		"--action", "github:write",
		"--resource", "acme/widgets",
	})

	w.Close()
	os.Stderr = origStderr
	var stderrBuf bytes.Buffer
	io.Copy(&stderrBuf, r)
	stderr := stderrBuf.String()

	if exitCode != 1 {
		t.Fatalf("expected exit code 1 (deny), got %d", exitCode)
	}

	// The enrollment URL must not appear in stderr logs. The URL contains
	// a sensitive claim secret and should never be written to info-level logs.
	if strings.Contains(stderr, "sensitive-enroll.test") {
		t.Error("enrollment URL leaked into stderr logs")
	}
	if strings.Contains(stderr, "secret-token") {
		t.Error("enrollment claim secret leaked into stderr logs")
	}
}
