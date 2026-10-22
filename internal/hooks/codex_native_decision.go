package hooks

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type codexPolicyRunner func(context.Context, string, string, []string) ([]byte, error)

// CodexNativeDecision asks Codex's own execpolicy evaluator for the rule
// decision behind a simple shell command. It never blocks the tool call: if
// the command cannot be checked exactly, the Codex binary or rules are
// unavailable, or the evaluator fails, the result is unknown.
func CodexNativeDecision(ctx context.Context, in ToolInput) string {
	if !strings.EqualFold(in.EventName, "PreToolUse") ||
		(!strings.EqualFold(in.ToolName, "Bash") && !strings.EqualFold(in.ToolName, "exec_command")) ||
		!filepath.IsAbs(in.CWD) {
		return "unknown"
	}
	argv, ok := simpleCodexCommand(in.ToolInput)
	if !ok {
		return "unknown"
	}
	binary, err := exec.LookPath("codex")
	if err != nil {
		return "unknown"
	}
	home := os.Getenv("CODEX_HOME")
	if home == "" {
		userHome, err := os.UserHomeDir()
		if err != nil {
			return "unknown"
		}
		home = filepath.Join(userHome, ".codex")
	}
	home, err = filepath.Abs(home)
	if err != nil {
		return "unknown"
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return codexPolicyDecision(ctx, binary, filepath.Join(home, "rules"), in.CWD, argv, runCodexPolicy)
}

func simpleCodexCommand(raw json.RawMessage) ([]string, bool) {
	var input struct {
		Command string `json:"command"`
		Cmd     string `json:"cmd"`
	}
	if json.Unmarshal(raw, &input) != nil {
		return nil, false
	}
	command := input.Command
	if command == "" {
		command = input.Cmd
	}
	if command == "" {
		return nil, false
	}
	// execpolicy check accepts argv tokens, not a shell program. Only pass
	// commands whose tokenization is unambiguous; shell syntax stays unknown.
	for _, r := range command {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			strings.ContainsRune("_./:@%+=,- \t", r) {
			continue
		}
		return nil, false
	}
	argv := strings.Fields(command)
	return argv, len(argv) > 0
}

func codexPolicyDecision(ctx context.Context, binary, rulesDir, cwd string, argv []string, run codexPolicyRunner) string {
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return "unknown"
	}
	var rules []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rules") {
			continue
		}
		rules = append(rules, filepath.Join(rulesDir, entry.Name()))
	}
	if len(rules) == 0 {
		return "unknown"
	}
	sort.Strings(rules)
	args := []string{"execpolicy", "check"}
	for _, rule := range rules {
		args = append(args, "--rules", rule)
	}
	args = append(args, "--")
	args = append(args, argv...)
	output, err := run(ctx, binary, cwd, args)
	if err != nil {
		return "unknown"
	}
	var result struct {
		Decision string `json:"decision"`
	}
	if json.Unmarshal(output, &result) != nil {
		return "unknown"
	}
	switch result.Decision {
	case "allow":
		return "allow"
	case "forbidden":
		return "deny"
	default:
		return "unknown"
	}
}

func runCodexPolicy(ctx context.Context, binary, cwd string, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = cwd
	return cmd.Output()
}
