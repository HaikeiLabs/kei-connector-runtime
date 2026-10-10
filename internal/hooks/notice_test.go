package hooks

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// mockSubjectSource returns a fixed subject for testing.
type mockSubjectSource struct {
	subject string
	err     error
}

func (m *mockSubjectSource) Subject(_ context.Context) (string, error) {
	return m.subject, m.err
}

func TestWriteNoticeFormat(t *testing.T) {
	for _, harness := range []string{"claude", "codex", "opencode"} {
		t.Run(harness, func(t *testing.T) {
			var buf bytes.Buffer
			msg := "test message"
			if err := writeNotice(&buf, harness, msg); err != nil {
				t.Fatal(err)
			}
			line := strings.TrimSpace(buf.String())
			var parsed struct {
				SystemMessage string `json:"systemMessage"`
			}
			if err := json.Unmarshal([]byte(line), &parsed); err != nil {
				t.Fatalf("writeNotice output is not valid JSON: %v", err)
			}
			if parsed.SystemMessage != msg {
				t.Fatalf("systemMessage = %q, want %q", parsed.SystemMessage, msg)
			}
		})
	}
}

func TestWriteNoticeNilWriter(t *testing.T) {
	if err := writeNotice(nil, "claude", "msg"); err != nil {
		t.Fatal(err)
	}
}

func TestWriteNoticeIncludesNewline(t *testing.T) {
	var buf bytes.Buffer
	if err := writeNotice(&buf, "claude", "hello"); err != nil {
		t.Fatal(err)
	}
	data := buf.String()
	if len(data) < 2 || data[len(data)-1] != '\n' {
		t.Fatalf("writeNotice output should end with newline: %q", data)
	}
}

func TestLoginNudgeAppearsWhenNoSubject(t *testing.T) {
	stateDir := t.TempDir()
	var stdout bytes.Buffer
	cfg := Config{
		RuntimeStateDir: stateDir,
		SubjectSource:   &mockSubjectSource{subject: ""},
	}
	input := `{"tool_name":"Bash","tool_input":{"command":"git status"},"session_id":"s1","native_decision":"ask"}`
	if code := ReportPermissions([]string{"claude", "--harness", "h1", "--session", "sess-1"}, strings.NewReader(input), &stdout, cfg); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(stdout.String(), "kei login") {
		t.Fatalf("login nudge missing: %q", stdout.String())
	}
}

func TestLoginNudgeRateLimited(t *testing.T) {
	stateDir := t.TempDir()
	var stdout bytes.Buffer
	cfg := Config{
		RuntimeStateDir: stateDir,
		SubjectSource:   &mockSubjectSource{subject: ""},
	}
	input := `{"tool_name":"Bash","tool_input":{"command":"git status"},"session_id":"s1","native_decision":"ask"}`

	// First call: nudge should appear
	if code := ReportPermissions([]string{"claude", "--harness", "h1", "--session", "sess-1"}, strings.NewReader(input), &stdout, cfg); code != 0 {
		t.Fatalf("first call exit = %d", code)
	}
	if !strings.Contains(stdout.String(), "kei login") {
		t.Fatalf("first call: login nudge missing: %q", stdout.String())
	}

	// Second call: nudge should be rate-limited (no output)
	var stdout2 bytes.Buffer
	if code := ReportPermissions([]string{"claude", "--harness", "h1", "--session", "sess-1"}, strings.NewReader(input), &stdout2, cfg); code != 0 {
		t.Fatalf("second call exit = %d", code)
	}
	if stdout2.Len() != 0 {
		t.Fatalf("second call: expected rate-limited (no output), got %q", stdout2.String())
	}
}

func TestNoNudgeWhenSubjectPresent(t *testing.T) {
	var stdout bytes.Buffer
	cfg := Config{
		SubjectSource: &mockSubjectSource{subject: "user-123"},
	}
	input := `{"tool_name":"Bash","tool_input":{"command":"git status"},"session_id":"s1","native_decision":"ask"}`
	if code := ReportPermissions([]string{"claude", "--harness", "h1", "--session", "sess-1"}, strings.NewReader(input), &stdout, cfg); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no nudge when subject is present, got: %q", stdout.String())
	}
}

func TestNudgeKeyFileUsesHash(t *testing.T) {
	stateDir := t.TempDir()
	path := nudgeKeyFile(stateDir, "my-session-id")
	if !strings.HasPrefix(path, stateDir) {
		t.Fatalf("path %q should be under state dir %q", path, stateDir)
	}
	if !strings.Contains(path, "nudge") {
		t.Fatalf("path %q should contain nudge subdir", path)
	}
	// Verify it's a hex-encoded SHA256 hash (64 hex chars)
	parts := strings.Split(path, "/")
	filename := parts[len(parts)-1]
	if len(filename) != 64 {
		t.Fatalf("expected 64-char hex hash, got %q (len=%d)", filename, len(filename))
	}
}

func TestNudgeKeyFileBlankSession(t *testing.T) {
	stateDir := t.TempDir()
	path := nudgeKeyFile(stateDir, "")
	if !strings.HasSuffix(path, ".nobody") {
		t.Fatalf("blank session should use fallback key, got %q", path)
	}
}

func TestRecentlyNudged(t *testing.T) {
	stateDir := t.TempDir()
	if recentlyNudged(stateDir, "sess-1") {
		t.Fatal("expected false for non-existent file")
	}
	if err := markNudged(stateDir, "sess-1"); err != nil {
		t.Fatal(err)
	}
	if !recentlyNudged(stateDir, "sess-1") {
		t.Fatal("expected true after marking nudged")
	}
}

func TestRecentlyNudgedEmptyStateDir(t *testing.T) {
	if recentlyNudged("", "sess-1") {
		t.Fatal("expected false for empty state dir")
	}
}

func TestMarkNudgedEmptyStateDir(t *testing.T) {
	if err := markNudged("", "sess-1"); err != nil {
		t.Fatal(err)
	}
}

func TestRecentlyNudgedExpired(t *testing.T) {
	stateDir := t.TempDir()
	if err := markNudged(stateDir, "sess-1"); err != nil {
		t.Fatal(err)
	}
	// Manually backdate the file to exceed the rate limit window
	old := time.Now().Add(-(nudgeRateLimit + time.Minute))
	if err := os.Chtimes(nudgeKeyFile(stateDir, "sess-1"), old, old); err != nil {
		t.Fatal(err)
	}
	if recentlyNudged(stateDir, "sess-1") {
		t.Fatal("expected false after rate limit window has expired")
	}
}

func TestNudgeDirectoryCreation(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "deep", "nested")
	if err := markNudged(stateDir, "sess-1"); err != nil {
		t.Fatal(err)
	}
	if !recentlyNudged(stateDir, "sess-1") {
		t.Fatal("expected true after marking nudged in nested dir")
	}
}

func TestNudgeUsesCorrectSessionKey(t *testing.T) {
	stateDir := t.TempDir()
	var stdout1, stdout2 bytes.Buffer
	cfg := Config{
		RuntimeStateDir: stateDir,
		SubjectSource:   &mockSubjectSource{subject: ""},
	}
	input := `{"tool_name":"Bash","tool_input":{"command":"git status"},"session_id":"s1","native_decision":"ask"}`

	// First session gets a nudge
	ReportPermissions([]string{"claude", "--harness", "h1", "--session", "sess-a"}, strings.NewReader(input), &stdout1, cfg)
	if !strings.Contains(stdout1.String(), "kei login") {
		t.Fatalf("first session nudge missing: %q", stdout1.String())
	}

	// Second session (different key) should also get a nudge (not rate-limited)
	ReportPermissions([]string{"claude", "--harness", "h1", "--session", "sess-b"}, strings.NewReader(input), &stdout2, cfg)
	if !strings.Contains(stdout2.String(), "kei login") {
		t.Fatalf("second session nudge missing: %q", stdout2.String())
	}
}

func TestExpiredBundleNoticeUsesWriteNotice(t *testing.T) {
	stateDir := t.TempDir()
	policyDir := filepath.Join(stateDir, "policy")
	if err := os.Mkdir(policyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "bundle.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "state.json"), []byte(`{"state":"expired","highest_bundle_version":1,"bundle_digest":"sha256:test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, harness := range []string{"claude", "codex", "opencode"} {
		t.Run(harness, func(t *testing.T) {
			var stdout bytes.Buffer
			input := `{"tool_name":"Bash","tool_input":{"command":"git status"},"native_decision":"ask"}`
			code := ReportPermissions([]string{harness, "--harness", "h1"}, strings.NewReader(input), &stdout, Config{RuntimeStateDir: stateDir})
			if code != 0 {
				t.Fatalf("exit = %d", code)
			}
			if !strings.Contains(stdout.String(), "kei harness sync") {
				t.Fatalf("renewal prompt missing for %s: %q", harness, stdout.String())
			}
			if strings.Contains(stdout.String(), "permissionDecision") {
				t.Fatalf("renewal prompt altered native decision for %s: %s", harness, stdout.String())
			}
		})
	}
}
