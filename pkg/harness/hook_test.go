package harness

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type captureRecorder struct{ event HarnessToolEvent }

func (r *captureRecorder) RecordHarnessEvent(_ context.Context, e HarnessToolEvent) error {
	r.event = e
	return nil
}

func TestClaudeHookReportsDigestWithoutDecisionOrArguments(t *testing.T) {
	r := &captureRecorder{}
	var out strings.Builder
	err := (ClaudeCodeAdapter{}).Hook(context.Background(), r, Harness{ID: "h-1", Kind: ClaudeCode}, strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"git status"},"session_id":"s","tool_use_id":"u"}`), &out)
	if err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("hook wrote stdout: %q", out.String())
	}
	if r.event.Schema != "kei.harness-tool-event/v1" || r.event.Tool != "claude_code.bash" || r.event.NativeDecision != "unknown" || r.event.ArgsDigest == "" || r.event.Argv0 != "git" {
		t.Fatalf("event = %#v", r.event)
	}
	b, _ := json.Marshal(r.event)
	if strings.Contains(string(b), "git status") {
		t.Fatalf("raw arguments leaked in event: %s", b)
	}
}

func TestManifestFromDiscoveryUsesV3HarnessRoutes(t *testing.T) {
	m := ManifestFromDiscovery(Discovery{BuiltIns: []Tool{{Name: "codex.read", Source: "codex", OperationClass: "read"}}, MCP: []Tool{{Name: "codex.mcp.linear.create_issue", Source: "mcp", OperationClass: "write"}}})
	if m.Schema != "kei.tool-manifest/v3" || len(m.Tools) != 2 {
		t.Fatalf("manifest = %#v", m)
	}
	for _, tool := range m.Tools {
		if tool.Route.HarnessExecutor.Executor == "" || tool.Route.HarnessExecutor.Registration == "" {
			t.Fatalf("tool missing explicit harness route: %#v", tool)
		}
	}
}
