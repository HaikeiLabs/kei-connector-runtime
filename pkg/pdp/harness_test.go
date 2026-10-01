package pdp

import (
	"context"
	"testing"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

func TestEvaluateHarness(t *testing.T) {
	// The vendored schemas predate ADR-029 (kei#682): they reject harness:
	// sources and multi-token shell: destinations until #72 re-pins them, so
	// these cases validate only the closed bundle shape, not the patterns.
	useValidator(t, func([]byte) error { return nil })
	policies := []testPolicy{
		{ID: "pol-1", Src: "harness:codex", Dst: "shell:git push", Action: "deny"},
		{ID: "pol-2", Src: "*", Dst: "shell:git", Action: "permit"},
		{ID: "pol-3", Src: "user:u-alice", Dst: "skill:deploy", Action: "permit"},
		{ID: "pol-4", Src: "harness:claude_code", Dst: "path:~/code/**/src/*.go", Action: "permit"},
		{ID: "pol-5", Src: "*", Dst: "mcp:linear", Action: "permit"},
		{ID: "pol-6", Src: "agent:agent-x", Dst: "tool:claude_code.edit", Action: "permit"},
		{ID: "pol-7", Src: "*", Dst: "tool:codex.view", Action: "permit", AgentID: "agent-y"},
		{ID: "pol-8", Src: "*", Dst: "shell:*", Action: "permit"},
		{ID: "pol-9", Src: "harness:11111111-2222-3333-4444-555555555555", Dst: "shell:make test", Action: "permit"},
		{ID: "pol-a", Src: "*", Dst: "skill:*", Action: "deny"},
		{ID: "pol-b", Src: "*", Dst: "*", Action: "permit"},
	}
	harnessID := "11111111-2222-3333-4444-555555555555"
	cases := []struct {
		name     string
		call     HarnessCall
		outcome  string
		policyID string
	}{
		{name: "harness-kind deny on an argv prefix", call: HarnessCall{Kind: "codex", Argv: []string{"git", "push", "origin"}}, outcome: "deny", policyID: "pol-1"},
		{name: "deny is per kind", call: HarnessCall{Kind: "claude_code", Argv: []string{"git", "push"}}, outcome: "permit", policyID: "pol-2"},
		{name: "argv0 is compared as written", call: HarnessCall{Kind: "claude_code", Argv: []string{"/usr/bin/git", "status"}}, outcome: "unmatched"},
		{name: "prefix is by whole token", call: HarnessCall{Kind: "codex", Argv: []string{"git", "pushx"}}, outcome: "permit", policyID: "pol-2"},
		{name: "harness id source", call: HarnessCall{Kind: "opencode", HarnessID: harnessID, Argv: []string{"make", "test", "-j4"}}, outcome: "permit", policyID: "pol-9"},
		{name: "shell is never permitted by shell:* or *", call: HarnessCall{Kind: "opencode", Argv: []string{"make", "test"}}, outcome: "unmatched"},
		{name: "human source is not renderable", call: HarnessCall{Kind: "claude_code", Skill: "deploy"}, outcome: "not_renderable", policyID: "pol-3"},
		{name: "skill wildcard deny", call: HarnessCall{Kind: "claude_code", Skill: "wiki"}, outcome: "deny", policyID: "pol-a"},
		{name: "path glob with ** and *", call: HarnessCall{Kind: "claude_code", Home: "/home/u", Path: "/home/u/code/kei/pkg/src/main.go"}, outcome: "permit", policyID: "pol-4"},
		{name: "** matches zero segments", call: HarnessCall{Kind: "claude_code", Home: "/home/u", Path: "/home/u/code/src/a.go"}, outcome: "permit", policyID: "pol-4"},
		{name: "* stays within one segment", call: HarnessCall{Kind: "claude_code", Home: "/home/u", Path: "/home/u/code/src/x/a.go"}, outcome: "permit", policyID: "pol-b"},
		{name: "path glob needs a home for ~/", call: HarnessCall{Kind: "claude_code", Path: "/home/u/code/src/a.go"}, outcome: "not_renderable", policyID: "pol-4"},
		{name: "relative path cannot be evaluated", call: HarnessCall{Kind: "claude_code", Path: "code/src/a.go"}, outcome: "not_renderable"},
		{name: "mcp server name", call: HarnessCall{Kind: "codex", MCPServer: "linear", MCPTool: "create_issue"}, outcome: "permit", policyID: "pol-5"},
		{name: "agent source", call: HarnessCall{Kind: "claude_code", AgentID: "agent-x", Tool: "claude_code.edit"}, outcome: "permit", policyID: "pol-6"},
		{name: "scope.agent_id skips other agents", call: HarnessCall{Kind: "codex", AgentID: "agent-z", Tool: "codex.view"}, outcome: "permit", policyID: "pol-b"},
		{name: "unknown harness kind", call: HarnessCall{Kind: "cursor", Tool: "cursor.edit"}, outcome: "not_renderable"},
	}
	e, _, _ := newTestEvaluator(t, testNow, testBundle(t, testNow, 42, policies, nil), nil)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := e.EvaluateHarness(context.Background(), tc.call)
			if err != nil {
				t.Fatal(err)
			}
			if got.Outcome != tc.outcome || got.PolicyID != tc.policyID {
				t.Fatalf("got %+v, want outcome=%s policy=%s", got, tc.outcome, tc.policyID)
			}
		})
	}
	t.Run("no bundle renders nothing", func(t *testing.T) {
		empty, _, _ := newTestEvaluator(t, testNow, nil, nil)
		got, _ := empty.EvaluateHarness(context.Background(), HarnessCall{Kind: "codex", Argv: []string{"git"}})
		if got.Outcome != policybundle.HarnessNotRenderable {
			t.Fatalf("got %+v", got)
		}
	})
}
