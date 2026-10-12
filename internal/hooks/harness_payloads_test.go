package hooks

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHarnessPayloadGoldens runs each real-shape harness payload through the
// rendered hook command (kei-proxy hook <kind>, no --harness, as kei-cli
// renders it) and compares the spooled records with the golden file beside
// the fixture. observed_at is the only field dropped before comparing.
//
// opencode/*.json are the envelopes the kei-cli kei-audit.js plugin pipes to
// kei-proxy hook opencode (OpenCode 1.19.0 plugin hooks); codex/*.json are
// Codex 0.162.1 hook stdin (codex-rs/hooks/schema/generated). An empty golden
// means the event is accepted and writes no tool record.
func TestHarnessPayloadGoldens(t *testing.T) {
	for _, kind := range []string{"codex", "opencode"} {
		fixtures, err := filepath.Glob(filepath.Join("testdata", "hooks", kind, "*.json"))
		if err != nil || len(fixtures) == 0 {
			t.Fatalf("no %s fixtures: %v", kind, err)
		}
		for _, fixture := range fixtures {
			name := strings.TrimSuffix(filepath.Base(fixture), ".json")
			t.Run(kind+"/"+name, func(t *testing.T) {
				input, err := os.ReadFile(fixture)
				if err != nil {
					t.Fatal(err)
				}
				want, err := os.ReadFile(strings.TrimSuffix(fixture, ".json") + ".golden.jsonl")
				if err != nil {
					t.Fatal(err)
				}
				var spool bytes.Buffer
				cfg := Config{RuntimeStateDir: t.TempDir(), AppendAudit: func(record []byte) error {
					spool.Write(record)
					spool.WriteByte('\n')
					return nil
				}}
				var stdout, stderr bytes.Buffer
				if code := Run([]string{kind}, bytes.NewReader(input), &stdout, &stderr, cfg); code != 0 {
					t.Fatalf("exit = %d, stderr = %q", code, stderr.String())
				}
				if stdout.Len() != 0 {
					t.Fatalf("hook wrote deciding output: %q", stdout.String())
				}
				if got := withoutObservedAt(t, spool.Bytes()); got != withoutObservedAt(t, want) {
					t.Fatalf("records:\n got %s\nwant %s", got, withoutObservedAt(t, want))
				}
				for _, secret := range []string{"git status", "fixture output", "Show working tree status"} {
					if strings.Contains(spool.String(), secret) {
						t.Fatalf("raw tool arguments or result leaked into spool: %q", secret)
					}
				}
			})
		}
	}
}

// withoutObservedAt canonicalises JSONL records and drops observed_at, the
// one field that differs between runs.
func withoutObservedAt(t *testing.T, jsonl []byte) string {
	t.Helper()
	var out []string
	for line := range bytes.SplitSeq(bytes.TrimSpace(jsonl), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatalf("record %q: %v", line, err)
		}
		delete(record, "observed_at")
		b, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(b))
	}
	return strings.Join(out, "\n")
}

// TestOpencodeSessionEndClearsActiveSkill checks that session.deleted closes
// the session's skill attribution, so a later session reusing the id starts
// untagged.
func TestOpencodeSessionEndClearsActiveSkill(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{RuntimeStateDir: dir, AppendAudit: func([]byte) error { return nil }}
	skillCall := `{"phase":"pre","tool_name":"skill","session_id":"ses_fixture01","tool_use_id":"call_skill","tool_input":{"skill":"kei-proxy"}}`
	if code := Run([]string{"opencode"}, strings.NewReader(skillCall), &bytes.Buffer{}, &bytes.Buffer{}, cfg); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	store, err := OpenActiveSkillStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if skill, _ := store.Get("ses_fixture01"); skill != "kei-proxy" {
		t.Fatalf("active skill before SessionEnd = %q", skill)
	}
	end, err := os.ReadFile(filepath.Join("testdata", "hooks", "opencode", "session-deleted.json"))
	if err != nil {
		t.Fatal(err)
	}
	if code := Run([]string{"opencode"}, bytes.NewReader(end), &bytes.Buffer{}, &bytes.Buffer{}, cfg); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if skill, _ := store.Get("ses_fixture01"); skill != "" {
		t.Fatalf("active skill after SessionEnd = %q, want cleared", skill)
	}
}
