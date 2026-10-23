package connectorruntime

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

func TestAuthorizeAllowsCLIInstallationWithoutPlatformTenantID(t *testing.T) {
	stateDir := t.TempDir()
	now := time.Now().UTC()
	mustActivateTestBundle(t, stateDir, now)
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
			var req keiruntime.SubjectResolveRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode subject request: %v", err)
			}
			if req.UserID != "user-member-0001" {
				t.Errorf("user id=%q", req.UserID)
			}
			if req.TenantID != "" {
				t.Errorf("unexpected platform tenant id %q", req.TenantID)
			}
			_ = json.NewEncoder(w).Encode(policybundle.Subject{Status: "linked_approved", UserID: "user-member-0001", EffectiveGroups: []string{"members"}, OrgRoles: []string{"member"}, MaxAgeSeconds: 60})
		default:
			http.NotFound(w, r)
		}
	}))
	defer control.Close()
	t.Setenv("KEI_RUNTIME_TOKEN", "kh_live_runtime_test_token_1234567890")
	t.Setenv("KEI_RUNTIME_CONTROL_PLANE_URL", control.URL)
	t.Setenv("KEI_RUNTIME_STATE_DIR", stateDir)
	t.Setenv("KEI_PROXY_PLATFORM_TENANT_ID", "")
	var code int
	stdout := captureStdout(func() { code = runAuthorize([]string{"--tool", "web_search", "--user", "user-member-0001"}) })
	if code != 0 {
		t.Fatalf("local cli web_search denied: exit=%d stdout=%s", code, stdout)
	}
	var out AuthorizeOutput
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &out); err != nil {
		t.Fatalf("decode result: %v output=%s", err, stdout)
	}
	if out.Decision != "allow" {
		t.Fatalf("decision=%+v", out)
	}
	if subjectCalls != 1 {
		t.Fatalf("subject resolutions=%d; want 1", subjectCalls)
	}
}

// A runtime resolves subjects at the configured control plane.
func TestAuthorizeResolvesSubjectAtControlPlane(t *testing.T) {
	stateDir := t.TempDir()
	mustActivateTestBundle(t, stateDir, time.Now().UTC())
	workspace := "ws-fixture-0001"
	subjectCalls := 0
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/runtime/whoami":
			_ = json.NewEncoder(w).Encode(RuntimeIdentity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: &workspace, Platform: "discord", Status: "active", BindingStatus: "verified"})
		case "/api/v1/runtime:heartbeat":
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/runtime/subject-attributes:resolve":
			subjectCalls++
			if got := r.Header.Get("Authorization"); got != "Bearer kh_live_runtime_test_token_1234567890" {
				t.Errorf("control-plane authorization header missing installation token")
			}
			_ = json.NewEncoder(w).Encode(policybundle.Subject{Status: "linked_approved", UserID: "user-member-0001", EffectiveGroups: []string{"members"}, OrgRoles: []string{"member"}, MaxAgeSeconds: 60})
		default:
			t.Errorf("unexpected control-plane request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer controlPlane.Close()

	t.Setenv("KEI_RUNTIME_TOKEN", "kh_live_runtime_test_token_1234567890")
	t.Setenv("KEI_RUNTIME_CONTROL_PLANE_URL", controlPlane.URL)
	t.Setenv("KEI_RUNTIME_STATE_DIR", stateDir)
	var code int
	stdout := captureStdout(func() {
		code = runAuthorize([]string{"--tool", "web_search", "--provider-user", "discord-member-0001"})
	})
	if code != 0 {
		t.Fatalf("local web_search denied: exit=%d stdout=%s", code, stdout)
	}
	if subjectCalls != 1 {
		t.Fatalf("control-plane subject resolutions=%d; want 1", subjectCalls)
	}
}

func TestRunAuthorizeAcceptsInvokingSubjectFlag(t *testing.T) {
	t.Setenv("KEI_RUNTIME_TOKEN", "kh_live_runtime_test_token_1234567890")
	stderr := captureStderr(func() {
		if code := runAuthorize([]string{"--tool", "web_search", "--invoking-subject", "victim"}); code != 1 {
			t.Fatalf("exit = %d, want startup failure", code)
		}
	})
	if strings.Contains(stderr, "flag provided but not defined") {
		t.Fatalf("invoking-subject flag rejected: %s", stderr)
	}
}

func TestAuthorizeUsesPersistedBundleAndOnlineSubjectForUserDefault(t *testing.T) {
	stateDir := t.TempDir()
	now := time.Now().UTC()
	mustActivateTestBundle(t, stateDir, now)
	workspace := "ws-fixture-0001"
	authorizeCalls := 0
	subjectCalls := 0
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/runtime/whoami":
			_ = json.NewEncoder(w).Encode(RuntimeIdentity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: &workspace, Platform: "discord", Status: "active", BindingStatus: "verified"})
		case "/api/v1/runtime:heartbeat":
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/runtime/subject-attributes:resolve":
			subjectCalls++
			var req keiruntime.SubjectResolveRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode subject request: %v", err)
			}
			if req.PlatformUserID != "discord-member-0001" {
				t.Errorf("platform user=%q", req.PlatformUserID)
			}
			_ = json.NewEncoder(w).Encode(policybundle.Subject{Status: "linked_approved", UserID: "user-member-0001", EffectiveGroups: []string{"members"}, OrgRoles: []string{"member"}, MaxAgeSeconds: 60})
		case "/api/v1/authorize":
			authorizeCalls++
			http.Error(w, "must not call per-request PDP", 500)
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
		code = runAuthorize([]string{"--tool", "web_search", "--provider-user", "discord-member-0001"})
	})
	if code != 0 {
		t.Fatalf("local web_search denied: exit=%d stdout=%s", code, stdout)
	}
	var out AuthorizeOutput
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &out); err != nil {
		t.Fatalf("decode result: %v output=%s", err, stdout)
	}
	if out.Decision != "allow" {
		t.Fatalf("decision=%+v", out)
	}
	if authorizeCalls != 0 || subjectCalls != 1 {
		t.Fatalf("catalog authorize calls=%d subject resolutions=%d", authorizeCalls, subjectCalls)
	}
}
