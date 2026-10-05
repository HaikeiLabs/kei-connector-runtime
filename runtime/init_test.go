package runtime

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRunInitMemberSuccess pins the documented CLI output contract (KEI-108):
// the provisioning result goes to stdout as a single JSON object, stdout is
// never used for diagnostics, and stderr is empty on success.
func TestRunInitMemberSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/initialize" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"user_id":"u1","org_id":"o1","role":"member","group_id":"g1","initialized":true}`))
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	code := RunInit([]string{"--member", "--user", "u1", "--org", "o1", "--abac-url", server.URL}, &stdout, &stderr, server.URL, "", false)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr: %s", code, stderr.String())
	}
	var result InitResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if result.Member == nil || result.Member.GroupID != "g1" || !result.Member.Initialized {
		t.Errorf("unexpected member result: %+v", result.Member)
	}
	if result.Agent != nil {
		t.Errorf("agent should be absent, got %+v", result.Agent)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr should be empty on success, got: %s", stderr.String())
	}
}

// TestRunInitAgentSuccess verifies the agent path forwards the org as a query
// parameter and the declared tool/scope context in the body.
func TestRunInitAgentSuccess(t *testing.T) {
	var gotOrg string
	var gotBody AgentInitRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOrg = r.URL.Query().Get("org_id")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"a1","status":"ready","initialized":true}`))
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	code := RunInit([]string{
		"--agent", "--org", "o1", "--name", "researcher",
		"--tools", "search_wiki,search_web", "--scopes", "wiki:read",
		"--abac-url", server.URL,
	}, &stdout, &stderr, server.URL, "", false)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr: %s", code, stderr.String())
	}
	if gotOrg != "o1" {
		t.Errorf("org_id query = %q, want o1", gotOrg)
	}
	if gotBody.Name != "researcher" {
		t.Errorf("body name = %q, want researcher", gotBody.Name)
	}
	if string(gotBody.DeclaredTools) != `["search_wiki","search_web"]` {
		t.Errorf("declared_tools = %s", string(gotBody.DeclaredTools))
	}
	if string(gotBody.DeclaredDataScopes) != `["wiki:read"]` {
		t.Errorf("declared_data_scopes = %s", string(gotBody.DeclaredDataScopes))
	}
	var result InitResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if result.Agent == nil || result.Agent.ID != "a1" || !result.Agent.Initialized {
		t.Errorf("unexpected agent result: %+v", result.Agent)
	}
}

// TestRunInitFailClosed pins the no-local-fallback contract at the CLI layer:
// an ABAC 500 yields a non-zero exit, an error on stderr, and clean stdout.
func TestRunInitFailClosed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "member initialization failed; retry: org not found", http.StatusInternalServerError)
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	code := RunInit([]string{"--member", "--user", "u1", "--org", "missing", "--abac-url", server.URL}, &stdout, &stderr, server.URL, "", false)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "500") {
		t.Errorf("stderr missing status: %s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout should be empty on error, got: %s", stdout.String())
	}
}

func TestRunInitNoOperation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := RunInit([]string{"--org", "o1"}, &stdout, &stderr, "", "", false); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "--member and/or --agent") {
		t.Errorf("stderr missing error: %s", stderr.String())
	}
}

func TestRunInitMissingOrg(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := RunInit([]string{"--member", "--user", "u1"}, &stdout, &stderr, "", "", false); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "--org is required") {
		t.Errorf("stderr missing error: %s", stderr.String())
	}
}

func TestRunInitMemberMissingUser(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := RunInit([]string{"--member", "--org", "o1"}, &stdout, &stderr, "", "", false); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "--user is required") {
		t.Errorf("stderr missing error: %s", stderr.String())
	}
}
