package connectorruntime

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

const lazySubjectToken = "kh_live_runtime_test_token_1234567890"

// activateTestBundleWithSrc activates the example bundle with the src_pattern
// of each named policy replaced.
func activateTestBundleWithSrc(t *testing.T, dir string, srcByPolicy map[string]string) {
	t.Helper()
	now := time.Now().UTC()
	var doc map[string]any
	if err := json.Unmarshal(unsignedExampleBundle(t, now), &doc); err != nil {
		t.Fatal(err)
	}
	for _, p := range doc["policy_set"].(map[string]any)["policies"].([]any) {
		policy := p.(map[string]any)
		if src, ok := srcByPolicy[policy["id"].(string)]; ok {
			policy["src_pattern"] = src
		}
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	store, err := policybundle.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(b, "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", now); err != nil {
		t.Fatal(err)
	}
}

// lazySubjectControlPlane serves runtime bootstrap and counts every request.
// subject-attributes:resolve answers resolveStatus (500 = broken).
type lazySubjectControlPlane struct {
	*httptest.Server
	mu    sync.Mutex
	paths map[string]int
}

func newLazySubjectControlPlane(t *testing.T, resolveStatus int) *lazySubjectControlPlane {
	t.Helper()
	cp := &lazySubjectControlPlane{paths: map[string]int{}}
	workspace := "ws-fixture-0001"
	cp.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cp.mu.Lock()
		cp.paths[r.URL.Path]++
		cp.mu.Unlock()
		switch r.URL.Path {
		case "/api/v1/runtime/whoami":
			_ = json.NewEncoder(w).Encode(RuntimeIdentity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: &workspace, Platform: "discord", Status: "active", BindingStatus: "verified"})
		case "/api/v1/runtime:heartbeat":
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/runtime/subject-attributes:resolve":
			if resolveStatus != http.StatusOK {
				http.Error(w, "subject resolution broken", resolveStatus)
				return
			}
			_ = json.NewEncoder(w).Encode(policybundle.Subject{Status: "linked_approved", UserID: "user-member-0001", EffectiveGroups: []string{"members"}, OrgRoles: []string{"member"}, MaxAgeSeconds: 60})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(cp.Close)
	return cp
}

func (cp *lazySubjectControlPlane) hits(path string) int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.paths[path]
}

func (cp *lazySubjectControlPlane) otherPaths(allowed ...string) []string {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	var other []string
	for p := range cp.paths {
		ok := false
		for _, a := range allowed {
			ok = ok || p == a
		}
		if !ok {
			other = append(other, p)
		}
	}
	return other
}

func runLazySubjectAuthorize(t *testing.T, cp *lazySubjectControlPlane, stateDir string, args ...string) (int, AuthorizeOutput) {
	t.Helper()
	t.Setenv("KEI_RUNTIME_TOKEN", lazySubjectToken)
	t.Setenv("KEI_RUNTIME_CONTROL_PLANE_URL", cp.URL)
	t.Setenv("KEI_RUNTIME_STATE_DIR", stateDir)
	var code int
	stdout := captureStdout(func() { code = runAuthorize(args) })
	var out AuthorizeOutput
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &out); err != nil {
		t.Fatalf("decode result: %v output=%s", err, stdout)
	}
	return code, out
}

// Identity is only for credentials: a local tool under a src:* policy is
// decided locally. Subject resolution is broken here and must never be called;
// the only control-plane traffic is the per-call runtime bootstrap.
func TestAuthorizeLocalToolWithWildcardPolicySkipsSubjectResolution(t *testing.T) {
	for _, args := range [][]string{
		{"--tool", "web_search", "--action", "tool:web_search", "--provider-user", "discord-member-0001"},
		{"--tool", "web_search", "--action", "tool:web_search", "--user", "user-member-0001"},
	} {
		t.Run(args[len(args)-2], func(t *testing.T) {
			stateDir := t.TempDir()
			activateTestBundleWithSrc(t, stateDir, map[string]string{"pol-baseline-search-web": "*"})
			cp := newLazySubjectControlPlane(t, http.StatusInternalServerError)

			code, out := runLazySubjectAuthorize(t, cp, stateDir, args...)
			if code != 0 || out.Decision != "allow" {
				t.Fatalf("local web_search under src:* denied: exit=%d out=%+v", code, out)
			}
			if n := cp.hits("/api/v1/runtime/subject-attributes:resolve"); n != 0 {
				t.Fatalf("subject resolution requests = %d, want 0", n)
			}
			if other := cp.otherPaths("/api/v1/runtime/whoami", "/api/v1/runtime:heartbeat"); len(other) != 0 {
				t.Fatalf("unexpected control-plane requests beyond bootstrap: %v", other)
			}
		})
	}
}

// A connector-bound tool resolves the subject even when its policy is
// agent-scoped and would otherwise decide without one.
func TestAuthorizeConnectorToolResolvesSubject(t *testing.T) {
	stateDir := t.TempDir()
	mustActivateTestBundle(t, stateDir, time.Now().UTC())
	cp := newLazySubjectControlPlane(t, http.StatusOK)

	code, out := runLazySubjectAuthorize(t, cp, stateDir, "--tool", "github.get_issue", "--provider-user", "discord-member-0001")
	if n := cp.hits("/api/v1/runtime/subject-attributes:resolve"); n != 1 {
		t.Fatalf("subject resolution requests = %d, want 1 (exit=%d out=%+v)", n, code, out)
	}
}

// A local tool whose policy is group-scoped resolves the subject, and a failed
// resolution still denies with subject_resolution_unavailable.
func TestAuthorizeGroupScopedLocalToolResolvesSubject(t *testing.T) {
	t.Run("resolves", func(t *testing.T) {
		stateDir := t.TempDir()
		mustActivateTestBundle(t, stateDir, time.Now().UTC())
		cp := newLazySubjectControlPlane(t, http.StatusOK)

		code, out := runLazySubjectAuthorize(t, cp, stateDir, "--tool", "web_search", "--action", "tool:web_search", "--provider-user", "discord-member-0001")
		if code != 0 || out.Decision != "allow" {
			t.Fatalf("group-scoped web_search denied: exit=%d out=%+v", code, out)
		}
		if n := cp.hits("/api/v1/runtime/subject-attributes:resolve"); n != 1 {
			t.Fatalf("subject resolution requests = %d, want 1", n)
		}
	})
	t.Run("resolution failure denies", func(t *testing.T) {
		stateDir := t.TempDir()
		mustActivateTestBundle(t, stateDir, time.Now().UTC())
		cp := newLazySubjectControlPlane(t, http.StatusInternalServerError)

		code, out := runLazySubjectAuthorize(t, cp, stateDir, "--tool", "web_search", "--action", "tool:web_search", "--provider-user", "discord-member-0001")
		if code == 0 || out.Decision != "deny" || out.ReasonCode != "subject_resolution_unavailable" {
			t.Fatalf("exit=%d out=%+v, want deny subject_resolution_unavailable", code, out)
		}
		if n := cp.hits("/api/v1/runtime/subject-attributes:resolve"); n != 1 {
			t.Fatalf("subject resolution requests = %d, want 1", n)
		}
	})
}
