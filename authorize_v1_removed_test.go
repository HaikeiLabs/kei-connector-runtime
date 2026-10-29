package connectorruntime

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// HAI-622-F: the one-shot authorize CLI no longer decides anything from a v1
// bundle. A persisted v1 bundle is denied as unsupported (exit 1, a decision),
// without resolving a subject or reaching a permit.
func TestRunAuthorizeDeniesAV1BundleAsUnsupported(t *testing.T) {
	stateDir := t.TempDir()
	mustActivateTestBundle(t, stateDir, time.Now().UTC())
	workspace := "ws-fixture-0001"
	subjectCalls := 0
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/runtime/whoami":
			_ = json.NewEncoder(w).Encode(RuntimeIdentity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: &workspace, Platform: "cli", Status: "active", BindingStatus: "verified"})
		case "/api/v1/runtime:heartbeat":
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/runtime/subject-attributes:resolve":
			subjectCalls++
			http.Error(w, "a v1 bundle must not reach subject resolution", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer control.Close()
	t.Setenv("KEI_RUNTIME_TOKEN", "kh_live_runtime_test_token_1234567890")
	t.Setenv("KEI_RUNTIME_CONTROL_PLANE_URL", control.URL)
	t.Setenv("KEI_RUNTIME_STATE_DIR", stateDir)
	var code int
	stdout := captureStdout(func() {
		code = runAuthorize([]string{"--tool", "web_search", "--user", "user-member-0001"})
	})
	if code != 1 {
		t.Fatalf("exit=%d, want 1 (a deny); stdout=%s", code, stdout)
	}
	var out AuthorizeOutput
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &out); err != nil {
		t.Fatalf("decode output %v: %s", err, stdout)
	}
	if out.Decision != "deny" || out.ReasonCode != "policy_bundle_unsupported" {
		t.Fatalf("decision=%+v, want deny policy_bundle_unsupported", out)
	}
	if subjectCalls != 0 {
		t.Fatalf("subject resolutions=%d, want 0", subjectCalls)
	}
}
