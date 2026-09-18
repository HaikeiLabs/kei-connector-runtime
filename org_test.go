package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRunOrgListWritesJSONToStdout pins the documented CLI output contract
// (KEI-108): machine-readable results go to stdout as JSON, stdout is never
// used for diagnostics, and the harness key is sent only as the
// Authorization header.
func TestRunOrgListWritesJSONToStdout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer kh_test_key" {
			t.Errorf("unexpected Authorization header: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"members":[{"org_id":"org1","user_id":"u1","role":"admin"}]}`))
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	code := runOrg([]string{"--org", "org1", "--list", "--key", "kh_test_key", "--abac-url", server.URL}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr: %s", code, stderr.String())
	}
	var members OrgMembersResponse
	if err := json.Unmarshal(stdout.Bytes(), &members); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if len(members.Members) != 1 || members.Members[0].UserID != "u1" {
		t.Errorf("unexpected members: %+v", members.Members)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr should be empty on success, got: %s", stderr.String())
	}
}

// TestRunOrgMissingKeyGoesToStderr pins the error contract: errors go to
// stderr with a non-zero exit code and stdout stays clean.
func TestRunOrgMissingKeyGoesToStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runOrg([]string{"--org", "org1", "--list"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "--key is required") {
		t.Errorf("stderr missing error: %s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout should be empty on error, got: %s", stdout.String())
	}
}

// TestRunOrgNon200GoesToStderr pins the error contract for upstream failures.
func TestRunOrgNon200GoesToStderr(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	code := runOrg([]string{"--org", "org1", "--list", "--key", "kh_test_key", "--abac-url", server.URL}, &stdout, &stderr)
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
