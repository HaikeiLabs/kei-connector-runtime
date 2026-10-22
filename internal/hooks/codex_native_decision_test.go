package hooks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCodexPolicyDecisionUsesNativeExecpolicyResult(t *testing.T) {
	rulesDir := filepath.Join(t.TempDir(), "rules")
	if err := os.MkdirAll(rulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"kei.rules", "default.rules"} {
		if err := os.WriteFile(filepath.Join(rulesDir, name), []byte("# fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	wantArgs := []string{
		"execpolicy", "check",
		"--rules", filepath.Join(rulesDir, "default.rules"),
		"--rules", filepath.Join(rulesDir, "kei.rules"),
		"--", "git", "reset", "--hard", "--help",
	}
	called := false
	got := codexPolicyDecision(context.Background(), "/codex", rulesDir, t.TempDir(), []string{"git", "reset", "--hard", "--help"}, func(_ context.Context, binary, cwd string, args []string) ([]byte, error) {
		called = true
		if binary != "/codex" || cwd == "" {
			t.Fatalf("runner binary=%q cwd=%q", binary, cwd)
		}
		if !reflect.DeepEqual(args, wantArgs) {
			t.Fatalf("runner args = %#v, want %#v", args, wantArgs)
		}
		return []byte(`{"matchedRules":[{"prefixRuleMatch":{"decision":"forbidden"}}],"decision":"forbidden"}`), nil
	})
	if !called || got != "deny" {
		t.Fatalf("decision = %q, runner called = %v; want deny", got, called)
	}
}

func TestCodexPolicyDecisionMapsOnlyNativeRuleOutcomes(t *testing.T) {
	rulesDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(rulesDir, "kei.rules"), []byte("# fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, output, want string
		err                error
	}{
		{name: "allow", output: `{"decision":"allow"}`, want: "allow"},
		{name: "deny", output: `{"decision":"forbidden"}`, want: "deny"},
		{name: "prompt rule remains undecided", output: `{"decision":"prompt"}`, want: "unknown"},
		{name: "no matching rule", output: `{"matchedRules":[]}`, want: "unknown"},
		{name: "malformed output", output: `{`, want: "unknown"},
		{name: "native checker error", err: errors.New("unavailable"), want: "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := codexPolicyDecision(context.Background(), "/codex", rulesDir, t.TempDir(), []string{"git", "status"}, func(context.Context, string, string, []string) ([]byte, error) {
				return []byte(tc.output), tc.err
			})
			if got != tc.want {
				t.Fatalf("decision = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSimpleCodexCommandRejectsShellSyntax(t *testing.T) {
	for _, command := range []string{"git reset --hard --help", "make test"} {
		got, ok := simpleCodexCommand(json.RawMessage(`{"command":` + mustJSONTest(t, command) + `}`))
		if !ok || len(got) == 0 {
			t.Fatalf("simple command %q was rejected", command)
		}
	}
	for _, command := range []string{"echo hi && git reset --hard", `git commit -m "two words"`, "echo $HOME", "git status | cat"} {
		if _, ok := simpleCodexCommand(json.RawMessage(`{"command":` + mustJSONTest(t, command) + `}`)); ok {
			t.Fatalf("shell command %q was treated as unambiguous argv", command)
		}
	}
}

func TestCodexPreHookRecordsNativeDecision(t *testing.T) {
	input := `{"session_id":"session-1","cwd":"/workspace","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git reset --hard --help"},"tool_use_id":"call-1"}`
	var records [][]byte
	cfg := Config{
		CodexDecisionSource: func(_ context.Context, in ToolInput) string {
			if in.CWD != "/workspace" || in.EventName != "PreToolUse" {
				t.Fatalf("Codex decision input = %+v", in)
			}
			return "deny"
		},
		AppendAudit: func(record []byte) error {
			records = append(records, append([]byte(nil), record...))
			return nil
		},
	}
	if code := Run([]string{"codex"}, bytes.NewBufferString(input), &bytes.Buffer{}, &bytes.Buffer{}, cfg); code != 0 {
		t.Fatalf("hook exit = %d", code)
	}
	if len(records) != 1 {
		t.Fatalf("audit events = %d, want one", len(records))
	}
	var record struct {
		Phase          string `json:"phase"`
		NativeDecision string `json:"native_decision"`
		ToolUseID      string `json:"tool_use_id"`
	}
	if err := json.Unmarshal(records[0], &record); err != nil {
		t.Fatal(err)
	}
	if record.Phase != "pre" || record.NativeDecision != "deny" || record.ToolUseID != "call-1" {
		t.Fatalf("audit record = %+v", record)
	}
}

func TestCodexNativeDecisionWithInstalledCLI(t *testing.T) {
	binary, err := exec.LookPath("codex")
	if err != nil {
		t.Skip("Codex CLI is not installed")
	}
	_ = binary
	home := t.TempDir()
	rulesDir := filepath.Join(home, "rules")
	if err := os.MkdirAll(rulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "kei.rules"), []byte(`prefix_rule(pattern=["git", "reset", "--hard"], decision="forbidden")`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_HOME", home)
	input := ToolInput{
		EventName: "PreToolUse",
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command":"git reset --hard --help"}`),
		CWD:       t.TempDir(),
	}
	if got := CodexNativeDecision(context.Background(), input); got != "deny" {
		t.Fatalf("Codex native decision = %q, want deny (binary %s)", got, binary)
	}
}

func mustJSONTest(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
