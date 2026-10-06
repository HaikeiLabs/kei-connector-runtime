package hooks

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const secretToolInput = `{"tool_name":"Bash","tool_input":{"command":"curl -H token:s3cr3t example.com"},"session_id":"sess-1","tool_use_id":"tu-1","hook_event_name":"PreToolUse","native_decision":"allow"}`

func TestHookWritesDefaultSpoolWithoutAuditEnv(t *testing.T) {
	t.Setenv("KEI_PROXY_AUDIT", "")
	os.Unsetenv("KEI_PROXY_AUDIT")
	stateDir := filepath.Join(t.TempDir(), "state")
	cfg := Config{RuntimeStateDir: stateDir, AppendAudit: SpoolAppender(os.Getenv("KEI_PROXY_AUDIT"), stateDir, 0)}
	if code := Run([]string{"claude", "--harness", "harness-123"}, strings.NewReader(secretToolInput), io.Discard, io.Discard, cfg); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	path := filepath.Join(stateDir, "audit", "harness-tool.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("default spool not written: %v", err)
	}
	if !bytes.Contains(data, []byte(`"event_class":"harness_tool"`)) || bytes.Count(data, []byte("\n")) != 1 {
		t.Fatalf("spool = %s", data)
	}
	if bytes.Contains(data, []byte("s3cr3t")) || bytes.Contains(data, []byte("tool_input")) {
		t.Fatalf("spool carries raw tool input: %s", data)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("spool mode = %v err=%v, want 0600", fi.Mode().Perm(), err)
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil || di.Mode().Perm() != 0o700 {
		t.Fatalf("spool dir mode = %v err=%v, want 0700", di.Mode().Perm(), err)
	}
}

func TestHookUsesAuditEnvPathWhenSet(t *testing.T) {
	stateDir := t.TempDir()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	cfg := Config{RuntimeStateDir: stateDir, AppendAudit: SpoolAppender(auditPath, stateDir, 0)}
	if code := Run([]string{"codex", "--harness", "harness-123"}, strings.NewReader(secretToolInput), io.Discard, io.Discard, cfg); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if _, err := os.Stat(auditPath); err != nil {
		t.Fatalf("KEI_PROXY_AUDIT spool not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "audit")); !os.IsNotExist(err) {
		t.Fatalf("default spool used despite KEI_PROXY_AUDIT: %v", err)
	}
}

func TestHookExitsZeroWhenDefaultSpoolUnwritable(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	// A regular file where the audit directory must go makes every append fail.
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "audit"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{RuntimeStateDir: stateDir, AppendAudit: SpoolAppender("", stateDir, 0)}
	if code := Run([]string{"opencode", "--harness", "harness-123"}, strings.NewReader(secretToolInput), io.Discard, io.Discard, cfg); code != 0 {
		t.Fatalf("exit = %d, want 0 on spool failure", code)
	}
}

func TestSpoolAppenderNilWithoutPaths(t *testing.T) {
	if SpoolAppender("", "", 0) != nil {
		t.Fatal("appender without any spool path")
	}
}
