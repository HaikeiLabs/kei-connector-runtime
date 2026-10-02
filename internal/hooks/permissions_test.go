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

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

func TestHookReportGoldenFixtures(t *testing.T) {
	for _, harness := range []string{"claude", "codex", "opencode"} {
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
			}
			if err := json.Unmarshal(input, &raw); err != nil {
				t.Fatal(err)
			}
			canonical := CanonicalJSON(raw.ToolInput)
			digest := sha256.Sum256(canonical)
			if got.Schema != "kei.harness-tool-event/v1" || got.HarnessID != "harness-123" || got.HarnessKind != harness {
				t.Fatalf("identity/schema = %+v", got)
			}
			wantTool := raw.ToolName
			if harness == "claude" || harness == "codex" || harness == "opencode" {
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
