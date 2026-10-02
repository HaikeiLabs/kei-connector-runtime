package harness

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestClaudeCodeDiscoversBuiltInsSkillsAndMCPTools(t *testing.T) {
	env := Env{HomeDir: filepath.Join("testdata", "claude")}
	d, err := ClaudeCodeAdapter{}.DiscoverTools(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.BuiltIns) == 0 || len(d.Skills) == 0 || len(d.MCP) == 0 {
		t.Fatalf("incomplete discovery: built-ins=%d skills=%d mcp=%d", len(d.BuiltIns), len(d.Skills), len(d.MCP))
	}
	if got := d.MCP[0]; got.Name != "claude_code.mcp.linear" || got.Selector != "mcp:linear" || got.OperationClass != "write" {
		t.Fatalf("unexpected MCP tool: %#v", got)
	}
	if got := d.Skills[0]; got.Name != "claude_code.skill.release_notes" || got.Selector != "skill:release-notes" {
		t.Fatalf("unexpected skill: %#v", got)
	}
	if !reflect.DeepEqual(d.Warnings, []string(nil)) {
		t.Fatalf("warnings = %#v", d.Warnings)
	}
	got, _ := json.Marshal(d)
	want, err := os.ReadFile(filepath.Join("testdata", "claude", "discovery.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var gotValue, wantValue any
	if err = json.Unmarshal(got, &gotValue); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(want, &wantValue); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("discovery differs from golden file\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}
