package hooks

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

func TestHookReportGoldenFixtures(t *testing.T) {
	for _, harness := range []string{"claude", "codex", "opencode", "cursor"} {
		t.Run(harness, func(t *testing.T) {
			input, err := os.ReadFile(filepath.Join("testdata", "hooks", harness+".json"))
			if err != nil {
				t.Fatal(err)
			}
			spool := filepath.Join(t.TempDir(), "audit.jsonl")
			var stdout bytes.Buffer
			cfg := Config{AppendAudit: func(record []byte) error { return os.WriteFile(spool, append(record, '\n'), 0600) }}
			if code := ReportPermissions([]string{harness, "--harness", "harness-123"}, bytes.NewReader(input), &stdout, cfg); code != 0 {
				t.Fatalf("exit = %d", code)
			}
			if stdout.Len() != 0 {
				t.Fatalf("hook wrote deciding output: %q", stdout.String())
			}
			var got permissionEvent
			line, err := os.ReadFile(spool)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(bytes.TrimSpace(line), &got); err != nil {
				t.Fatal(err)
			}
			var raw struct {
				ToolName  string          `json:"tool_name"`
				ToolInput json.RawMessage `json:"tool_input"`
				SessionID string          `json:"session_id"`
			}
			if err := json.Unmarshal(input, &raw); err != nil {
				t.Fatal(err)
			}
			canonical := CanonicalJSON(raw.ToolInput)
			digest := sha256.Sum256(canonical)
			if got.Schema != "kei.harness-tool-event/v1" || got.HarnessID != "harness-123" || got.HarnessKind != harness || got.HarnessSessionID != raw.SessionID {
				t.Fatalf("identity/schema = %+v", got)
			}
			wantTool := raw.ToolName
			if harness == "claude" || harness == "codex" || harness == "opencode" || harness == "cursor" {
				wantTool = "shell"
			}
			if got.Tool != wantTool || got.ArgsDigest != "sha256:"+hex.EncodeToString(digest[:]) {
				t.Fatalf("event = %+v", got)
			}
			if got.NativeDecision == "" {
				t.Fatal("native decision missing")
			}
			if strings.Contains(string(line), "git status") {
				t.Fatal("raw tool arguments leaked into spool")
			}
		})
	}
}

// TestReportedToolNormalizesShellNames pins the shell-tool normalization: a
// tool literally named Bash, shell or exec_command reports as "shell" with the
// command's argv0; other tools pass through unchanged.
func TestReportedToolNormalizesShellNames(t *testing.T) {
	cases := []struct {
		name  string
		tool  string
		raw   string
		want  string
		argv0 string
	}{
		{"bash", "Bash", `{"command":"git status"}`, "shell", "git"},
		{"codex", "exec_command", `{"cmd":"curl -s example.com"}`, "shell", "curl"},
		{"cursor-shell", "Shell", `{"command":"git status"}`, "shell", "git"},
		{"passthrough", "read_file", `{"file_path":"/tmp/x"}`, "read_file", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tool, argv0 := reportedTool(tc.tool, json.RawMessage(tc.raw))
			if tool != tc.want || argv0 != tc.argv0 {
				t.Fatalf("reportedTool(%q) = (%q, %q), want (%q, %q)", tc.tool, tool, argv0, tc.want, tc.argv0)
			}
		})
	}
}

// RenderedHookCLI is the command emitted by kei-cli internal/app/harness.go:1018
// for a Claude Code hook install spec. It must parse as `hook <kind> --harness <id>`.
const RenderedHookCLI = "kei-proxy hook claude --harness h-abc123"

func TestRunAcceptsRenderedContract(t *testing.T) {
	for _, harness := range []struct {
		kind    string
		fixture string
	}{{"claude", "claude.json"}, {"codex", "codex.json"}, {"opencode", "opencode.json"}, {"cursor", "cursor.json"}} {
		t.Run(harness.kind, func(t *testing.T) {
			input, err := os.ReadFile(filepath.Join("testdata", "hooks", harness.fixture))
			if err != nil {
				t.Fatal(err)
			}
			var spoolBuf bytes.Buffer
			cfg := Config{AppendAudit: func(record []byte) error {
				spoolBuf.Write(record)
				spoolBuf.WriteByte('\n')
				return nil
			}}
			var stdout, stderr bytes.Buffer
			// Exact argv from HookSpec: hook <kind> --harness <id>
			args := []string{harness.kind, "--harness", "h-abc123"}
			if code := Run(args, bytes.NewReader(input), &stdout, &stderr, cfg); code != 0 {
				t.Fatalf("Run(%v) exit = %d, stderr=%q", args, code, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("hook wrote deciding output: %q", stdout.String())
			}
			var got permissionEvent
			line, err := spoolBuf.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &got); err != nil {
				t.Fatal(err)
			}
			var raw struct {
				SessionID string `json:"session_id"`
			}
			if err := json.Unmarshal(input, &raw); err != nil {
				t.Fatal(err)
			}
			if got.Schema != "kei.harness-tool-event/v1" || got.HarnessID != "h-abc123" || got.HarnessKind != harness.kind || got.HarnessSessionID != raw.SessionID {
				t.Fatalf("identity/schema = %+v", got)
			}
			if got.NativeDecision == "" {
				t.Fatal("native decision missing")
			}
		})
	}
}

func TestRunBackwardCompat(t *testing.T) {
	input, err := os.ReadFile(filepath.Join("testdata", "hooks", "claude.json"))
	if err != nil {
		t.Fatal(err)
	}
	var spoolBuf bytes.Buffer
	cfg := Config{AppendAudit: func(record []byte) error {
		spoolBuf.Write(record)
		spoolBuf.WriteByte('\n')
		return nil
	}}
	var stdout, stderr bytes.Buffer
	// Legacy format: hook report <kind> --harness <id>
	args := []string{"report", "claude", "--harness", "h-legacy"}
	if code := Run(args, bytes.NewReader(input), &stdout, &stderr, cfg); code != 0 {
		t.Fatalf("Run(%v) exit = %d", args, code)
	}
	var got permissionEvent
	line, err := spoolBuf.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &got); err != nil {
		t.Fatal(err)
	}
	if got.HarnessKind != "claude" || got.HarnessID != "h-legacy" {
		t.Fatalf("event = %+v", got)
	}
}

func TestRunWithoutHarnessID(t *testing.T) {
	for _, harness := range []struct {
		kind    string
		fixture string
	}{{"claude", "claude.json"}, {"codex", "codex.json"}, {"opencode", "opencode.json"}, {"cursor", "cursor.json"}} {
		t.Run(harness.kind, func(t *testing.T) {
			input, err := os.ReadFile(filepath.Join("testdata", "hooks", harness.fixture))
			if err != nil {
				t.Fatal(err)
			}
			var spoolBuf bytes.Buffer
			cfg := Config{AppendAudit: func(record []byte) error {
				spoolBuf.Write(record)
				spoolBuf.WriteByte('\n')
				return nil
			}}
			var stdout, stderr bytes.Buffer
			// No --harness flag: the hook must still succeed and carry the kind + session_id.
			args := []string{harness.kind}
			if code := Run(args, bytes.NewReader(input), &stdout, &stderr, cfg); code != 0 {
				t.Fatalf("Run(%v) exit = %d, stderr=%q", args, code, stderr.String())
			}
			var got permissionEvent
			line, err := spoolBuf.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &got); err != nil {
				t.Fatal(err)
			}
			if got.HarnessID != "" {
				t.Fatalf("HarnessID = %q, want empty (no --harness flag)", got.HarnessID)
			}
			if got.HarnessKind != harness.kind {
				t.Fatalf("HarnessKind = %q, want %q", got.HarnessKind, harness.kind)
			}
			if got.HarnessSessionID == "" {
				t.Fatal("HarnessSessionID is empty, want a value from stdin or fallback")
			}
			if got.NativeDecision == "" {
				t.Fatal("native decision missing")
			}
		})
	}
}

func TestRunReturnsZeroForGarbageArgs(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"no-args", nil},
		{"empty-args", []string{}},
		{"unknown-subcommand", []string{"nope"}},
		{"bad-kind", []string{"bogus", "--harness", "h"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(tc.args, strings.NewReader(`{"tool_name":"Bash","tool_input":{},"native_decision":"ask"}`), &stdout, &stderr, Config{})
			if code != 0 {
				t.Fatalf("Run(%v) exit = %d", tc.args, code)
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want empty", stdout.String())
			}
		})
	}
}

func TestRunRenderedHookCLIFixture(t *testing.T) {
	// RenderedHookCLI is "kei-proxy hook claude --harness h-abc123" — verify
	// that splitting off the leading binary yields args that Run accepts.
	parts := splitHookCLI(RenderedHookCLI)
	if len(parts) < 3 || parts[0] != "claude" || parts[1] != "--harness" || parts[2] != "h-abc123" {
		t.Fatalf("RenderedHookCLI splits to %v, want [claude --harness h-abc123]", parts)
	}
	input := `{"tool_name":"Bash","tool_input":{"command":"git status"},"native_decision":"ask"}`
	var stdout, stderr bytes.Buffer
	code := Run(parts, strings.NewReader(input), &stdout, &stderr, Config{})
	if code != 0 {
		t.Fatalf("Run(%v) = %d, stderr=%q", parts, code, stderr.String())
	}
}

// splitHookCLI splits a rendered hook command like "kei-proxy hook claude --harness h-abc123"
// into args suitable for Run (dropping the leading binary and "hook" subcommand).
func splitHookCLI(cli string) []string {
	parts := strings.Fields(cli)
	// parts[0]="kei-proxy", parts[1]="hook" -> drop both
	if len(parts) > 2 {
		return parts[2:]
	}
	return nil
}

func TestHookReportAlwaysExitsZeroOnBadInputAndSpoolFailure(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		path  string
	}{{"bad-json", "{", filepath.Join(t.TempDir(), "audit")}, {"unwritable", `{"tool_name":"Bash","tool_input":{},"native_decision":"ask"}`, filepath.Join(t.TempDir(), "missing", "dir", "audit")}} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			code := ReportPermissions([]string{"claude", "--harness", "h"}, strings.NewReader(tc.input), &out, Config{AppendAudit: func([]byte) error { return os.WriteFile(tc.path, []byte("x"), 0600) }})
			if code != 0 || out.Len() != 0 {
				t.Fatalf("exit=%d stdout=%q", code, out.String())
			}
		})
	}
}

func TestHookReportPromptsClaudeToRenewExpiredBundle(t *testing.T) {
	stateDir := t.TempDir()
	policyDir := filepath.Join(stateDir, "policy")
	if err := os.Mkdir(policyDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "bundle.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "state.json"), []byte(`{"state":"expired","highest_bundle_version":1,"bundle_digest":"sha256:test"}`), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := policybundle.OpenStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if store.State() != policybundle.Expired {
		t.Fatalf("state = %s", store.State())
	}
	var stdout bytes.Buffer
	input := `{"tool_name":"Bash","tool_input":{"command":"git status"},"native_decision":"ask"}`
	code := ReportPermissions([]string{"claude", "--harness", "h1"}, strings.NewReader(input), &stdout, Config{RuntimeStateDir: stateDir})
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(stdout.String(), "kei harness sync") {
		t.Fatalf("renewal prompt missing: %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "permissionDecision") {
		t.Fatalf("renewal prompt altered native decision: %s", stdout.String())
	}
}

func TestCanonicalJSONSortsObjectKeys(t *testing.T) {
	if got := string(CanonicalJSON([]byte(`{"b":1,"a":2}`))); got != `{"a":2,"b":1}` {
		t.Fatalf("canonical JSON = %s", got)
	}
}

// TestOpencodeSkillTaggingAcrossSession verifies that an opencode skill tool
// call sets the session's active skill and that subsequent tool calls in the
// same session are tagged with it.
func TestOpencodeSkillTaggingAcrossSession(t *testing.T) {
	stateDir := t.TempDir()
	var spool []byte
	cfg := Config{
		RuntimeStateDir: stateDir,
		AppendAudit: func(record []byte) error {
			spool = append(spool, record...)
			spool = append(spool, '\n')
			return nil
		},
	}
	report := func(input string) {
		t.Helper()
		var stdout bytes.Buffer
		if code := ReportPermissions([]string{"opencode", "--harness", "h1"}, strings.NewReader(input), &stdout, cfg); code != 0 {
			t.Fatalf("exit = %d", code)
		}
	}
	report(`{"tool_name":"skill","tool_input":{"skill":"pdf"},"session_id":"s1","native_decision":"allow"}`)
	report(`{"tool_name":"bash","tool_input":{"command":"git status"},"session_id":"s1","native_decision":"allow"}`)
	report(`{"tool_name":"read","tool_input":{"file_path":"/tmp/x"},"session_id":"s1","native_decision":"allow"}`)

	lines := strings.Split(strings.TrimSpace(string(spool)), "\n")
	if len(lines) != 3 {
		t.Fatalf("spool lines = %d, want 3", len(lines))
	}
	for i, line := range lines {
		var ev permissionEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("unmarshal line %d: %v", i, err)
		}
		if ev.Skill != "pdf" {
			t.Fatalf("line %d skill = %q, want pdf", i, ev.Skill)
		}
	}
}

// TestOpencodeSkillChangesAcrossSessions verifies the active skill is keyed by
// session: a second session keeps its own skill, and a later skill call in the
// first session updates it.
func TestOpencodeSkillChangesAcrossSessions(t *testing.T) {
	stateDir := t.TempDir()
	var spool []byte
	cfg := Config{
		RuntimeStateDir: stateDir,
		AppendAudit: func(record []byte) error {
			spool = append(spool, record...)
			spool = append(spool, '\n')
			return nil
		},
	}
	report := func(input string) {
		t.Helper()
		var stdout bytes.Buffer
		if code := ReportPermissions([]string{"opencode", "--harness", "h1"}, strings.NewReader(input), &stdout, cfg); code != 0 {
			t.Fatalf("exit = %d", code)
		}
	}
	report(`{"tool_name":"skill","tool_input":{"skill":"pdf"},"session_id":"s1","native_decision":"allow"}`)
	report(`{"tool_name":"skill","tool_input":{"skill":"docx"},"session_id":"s2","native_decision":"allow"}`)
	report(`{"tool_name":"bash","tool_input":{"command":"ls"},"session_id":"s1","native_decision":"allow"}`)
	report(`{"tool_name":"bash","tool_input":{"command":"ls"},"session_id":"s2","native_decision":"allow"}`)

	lines := strings.Split(strings.TrimSpace(string(spool)), "\n")
	want := []string{"pdf", "docx", "pdf", "docx"}
	if len(lines) != len(want) {
		t.Fatalf("spool lines = %d, want %d", len(lines), len(want))
	}
	for i, line := range lines {
		var ev permissionEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("unmarshal line %d: %v", i, err)
		}
		if ev.Skill != want[i] {
			t.Fatalf("line %d skill = %q, want %q", i, ev.Skill, want[i])
		}
	}
}

// TestNonOpencodeHarnessesHaveNoSkill verifies claude and codex never carry a
// skill, even when the input is a skill-shaped tool call.
func TestNonOpencodeHarnessesHaveNoSkill(t *testing.T) {
	stateDir := t.TempDir()
	for _, kind := range []string{"claude", "codex"} {
		t.Run(kind, func(t *testing.T) {
			var spool []byte
			cfg := Config{
				RuntimeStateDir: stateDir,
				AppendAudit: func(record []byte) error {
					spool = append(spool, record...)
					return nil
				},
			}
			var stdout bytes.Buffer
			input := `{"tool_name":"skill","tool_input":{"skill":"pdf"},"session_id":"s1","native_decision":"allow"}`
			if code := ReportPermissions([]string{kind, "--harness", "h1"}, strings.NewReader(input), &stdout, cfg); code != 0 {
				t.Fatalf("exit = %d", code)
			}
			var ev permissionEvent
			if err := json.Unmarshal(spool, &ev); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if ev.Skill != "" {
				t.Fatalf("skill = %q, want empty for %s", ev.Skill, kind)
			}
			// The skill field (not the "tool":"skill" name) must be omitted.
			if bytes.Contains(spool, []byte(`"skill":"`)) {
				t.Fatalf("skill field present in spool: %s", spool)
			}
		})
	}
}

// TestHookPiSessionEventReportsHarnessTool pins the HAI-922 contract: the Pi
// extension runs `kei-proxy hook pi` (no --harness flag) with a session-level
// event whose pseudo tool is pi.session, and the hook writes exactly one
// harness_tool record with harness_kind "pi" and harness_session_id from the
// payload. The tool-less session path must not be involved: the collector
// quarantines tool-less records, so pi.session is what keeps the record.
func TestHookPiSessionEventReportsHarnessTool(t *testing.T) {
	input := `{"session_id":"s1","hook_event_name":"SessionStart","tool_name":"pi.session","tool_input":{},"phase":"pre","native_decision":"allow"}`
	var spool []byte
	cfg := Config{AppendAudit: func(record []byte) error {
		spool = append(spool, record...)
		spool = append(spool, '\n')
		return nil
	}}
	var stdout, stderr bytes.Buffer
	if code := ReportPermissions([]string{"pi"}, strings.NewReader(input), &stdout, cfg); code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("hook wrote deciding output: %q", stdout.String())
	}
	lines := strings.Split(strings.TrimSpace(string(spool)), "\n")
	if len(lines) != 1 {
		t.Fatalf("spool lines = %d, want exactly one record", len(lines))
	}
	var got permissionEvent
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatal(err)
	}
	if got.Schema != "kei.harness-tool-event/v1" || got.EventClass != "harness_tool" {
		t.Fatalf("schema/class = %s/%s, want kei.harness-tool-event/v1/harness_tool", got.Schema, got.EventClass)
	}
	if got.HarnessKind != "pi" {
		t.Fatalf("harness_kind = %q, want pi", got.HarnessKind)
	}
	if got.HarnessSessionID != "s1" {
		t.Fatalf("harness_session_id = %q, want s1", got.HarnessSessionID)
	}
	if got.Tool != "pi.session" || got.Phase != "pre" || got.NativeDecision != "allow" {
		t.Fatalf("event = %+v", got)
	}
}

// TestActiveSkillStorePersists verifies the store survives across store
// instances (simulating separate hook processes) and is keyed by session.
func TestActiveSkillStorePersists(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenActiveSkillStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set("s1", "pdf"); err != nil {
		t.Fatal(err)
	}
	if err := store.Set("s2", "docx"); err != nil {
		t.Fatal(err)
	}

	// A fresh instance reads the same values back.
	store2, err := OpenActiveSkillStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := store2.Get("s1"); got != "pdf" {
		t.Fatalf("Get(s1) = %q, want pdf", got)
	}
	if got, _ := store2.Get("s2"); got != "docx" {
		t.Fatalf("Get(s2) = %q, want docx", got)
	}
	if got, _ := store2.Get("unknown"); got != "" {
		t.Fatalf("Get(unknown) = %q, want empty", got)
	}
}

// TestActiveSkillStoreBlankDirFailsClosed verifies a blank state directory is
// an error rather than silently dropping attribution.
func TestActiveSkillStoreBlankDirFailsClosed(t *testing.T) {
	if _, err := OpenActiveSkillStore("   "); err == nil {
		t.Fatal("expected an error for a blank state directory")
	}
}
