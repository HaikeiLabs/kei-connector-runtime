package pdp

import (
	"context"
	"os"
	"path/filepath"
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
		reason   string
	}{
		{name: "harness-kind deny on an argv prefix", call: HarnessCall{Kind: "codex", Argv: []string{"git", "push", "origin"}}, outcome: "deny", policyID: "pol-1"},
		{name: "deny is per kind", call: HarnessCall{Kind: "claude_code", Argv: []string{"git", "push"}}, outcome: "permit", policyID: "pol-2"},
		{name: "argv0 is compared as written", call: HarnessCall{Kind: "claude_code", Argv: []string{"/usr/bin/git", "status"}}, outcome: "unmatched"},
		{name: "prefix is by whole token", call: HarnessCall{Kind: "codex", Argv: []string{"git", "pushx"}}, outcome: "permit", policyID: "pol-2"},
		{name: "harness id source", call: HarnessCall{Kind: "opencode", HarnessID: harnessID, Argv: []string{"make", "test", "-j4"}}, outcome: "permit", policyID: "pol-9"},
		{name: "shell is never permitted by shell:* or *", call: HarnessCall{Kind: "opencode", Argv: []string{"make", "test"}}, outcome: "unmatched"},
		{name: "human source is not renderable", call: HarnessCall{Kind: "claude_code", Skill: "deploy"}, outcome: "not_renderable", policyID: "pol-3", reason: policybundle.HarnessReasonHumanSource},
		{name: "skill wildcard deny", call: HarnessCall{Kind: "claude_code", Skill: "wiki"}, outcome: "deny", policyID: "pol-a"},
		{name: "path glob with ** and *", call: HarnessCall{Kind: "claude_code", Home: "/home/u", Path: "/home/u/code/kei/pkg/src/main.go"}, outcome: "permit", policyID: "pol-4"},
		{name: "** matches zero segments", call: HarnessCall{Kind: "claude_code", Home: "/home/u", Path: "/home/u/code/src/a.go"}, outcome: "permit", policyID: "pol-4"},
		{name: "* stays within one segment", call: HarnessCall{Kind: "claude_code", Home: "/home/u", Path: "/home/u/code/src/x/a.go"}, outcome: "permit", policyID: "pol-b"},
		{name: "path glob needs a home for ~/", call: HarnessCall{Kind: "claude_code", Path: "/home/u/code/src/a.go"}, outcome: "not_renderable", policyID: "pol-4", reason: policybundle.HarnessReasonDstNotRenderable},
		{name: "relative path cannot be evaluated", call: HarnessCall{Kind: "claude_code", Path: "code/src/a.go"}, outcome: "not_renderable", reason: policybundle.HarnessReasonPathNotAbsolute},
		{name: "mcp server name", call: HarnessCall{Kind: "codex", MCPServer: "linear", MCPTool: "create_issue"}, outcome: "permit", policyID: "pol-5"},
		{name: "agent source", call: HarnessCall{Kind: "claude_code", AgentID: "agent-x", Tool: "claude_code.edit"}, outcome: "permit", policyID: "pol-6"},
		{name: "scope.agent_id skips other agents", call: HarnessCall{Kind: "codex", AgentID: "agent-z", Tool: "codex.view"}, outcome: "permit", policyID: "pol-b"},
		{name: "unknown harness kind", call: HarnessCall{Kind: "cursor", Tool: "cursor.edit"}, outcome: "not_renderable", reason: policybundle.HarnessReasonUnsupportedKind},
		{name: "custom kind is known and evaluated via pdp", call: HarnessCall{Kind: "custom", Tool: "any_tool"}, outcome: "not_renderable", reason: policybundle.HarnessReasonEvaluateViaPDP},
	}
	e, _, _ := newTestEvaluator(t, testNow, testBundle(t, testNow, 42, policies, nil), nil)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := e.EvaluateHarness(context.Background(), tc.call)
			if err != nil {
				t.Fatal(err)
			}
			if got.Outcome != tc.outcome || got.PolicyID != tc.policyID || got.Reason != tc.reason {
				t.Fatalf("got %+v, want outcome=%s policy=%s reason=%s", got, tc.outcome, tc.policyID, tc.reason)
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

func TestEvaluateHarnessReasonCodes(t *testing.T) {
	useValidator(t, func([]byte) error { return nil })

	t.Run("unsupported_kind", func(t *testing.T) {
		policies := []testPolicy{
			{ID: "pol-1", Src: "*", Dst: "*", Action: "permit"},
		}
		e, _, _ := newTestEvaluator(t, testNow, testBundle(t, testNow, 42, policies, nil), nil)
		got, err := e.EvaluateHarness(context.Background(), HarnessCall{Kind: "cursor"})
		if err != nil {
			t.Fatal(err)
		}
		if got.Outcome != policybundle.HarnessNotRenderable || got.Reason != policybundle.HarnessReasonUnsupportedKind {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("evaluate_via_pdp", func(t *testing.T) {
		policies := []testPolicy{
			{ID: "pol-1", Src: "*", Dst: "*", Action: "permit"},
		}
		e, _, _ := newTestEvaluator(t, testNow, testBundle(t, testNow, 42, policies, nil), nil)
		got, err := e.EvaluateHarness(context.Background(), HarnessCall{Kind: "custom", Tool: "search"})
		if err != nil {
			t.Fatal(err)
		}
		if got.Outcome != policybundle.HarnessNotRenderable || got.Reason != policybundle.HarnessReasonEvaluateViaPDP {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("path_not_absolute", func(t *testing.T) {
		policies := []testPolicy{
			{ID: "pol-1", Src: "*", Dst: "path:relative/path", Action: "permit"},
		}
		e, _, _ := newTestEvaluator(t, testNow, testBundle(t, testNow, 42, policies, nil), nil)
		got, err := e.EvaluateHarness(context.Background(), HarnessCall{Kind: "claude_code", Path: "relative/path"})
		if err != nil {
			t.Fatal(err)
		}
		if got.Outcome != policybundle.HarnessNotRenderable || got.Reason != policybundle.HarnessReasonPathNotAbsolute {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("bundle_invalid", func(t *testing.T) {
		_, _, dir := newTestEvaluator(t, testNow, nil, nil)
		// Write garbage into the state file (bypass Activate, which would
		// reject it) so that check() returns Invalid and EvaluateHarness
		// surfaces the bundle_invalid reason.
		statePath := filepath.Join(dir, "state.json")
		if err := os.WriteFile(statePath, []byte(`{"highest_bundle_version":0,"audience":{"installation_id":"inst-1","org_id":"org-1","workspace_id":"ws-1"},"state":"invalid"}`), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "bundle.json"), []byte(`{}`), 0600); err != nil {
			t.Fatal(err)
		}
		e, err := New(dir, testAudience, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := e.EvaluateHarness(context.Background(), HarnessCall{Kind: "codex", Argv: []string{"git"}})
		if err != nil {
			t.Fatal(err)
		}
		if got.Outcome != policybundle.HarnessNotRenderable || got.Reason != policybundle.HarnessReasonBundleInvalid {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("human_source", func(t *testing.T) {
		policies := []testPolicy{
			{ID: "pol-1", Src: "user:u-alice", Dst: "skill:deploy", Action: "permit"},
		}
		e, _, _ := newTestEvaluator(t, testNow, testBundle(t, testNow, 42, policies, nil), nil)
		got, err := e.EvaluateHarness(context.Background(), HarnessCall{Kind: "claude_code", Skill: "deploy"})
		if err != nil {
			t.Fatal(err)
		}
		if got.Outcome != policybundle.HarnessNotRenderable || got.PolicyID != "pol-1" || got.Reason != policybundle.HarnessReasonHumanSource {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("dst_not_renderable", func(t *testing.T) {
		policies := []testPolicy{
			{ID: "pol-1", Src: "*", Dst: "path:~/code/**/src/*.go", Action: "permit"},
		}
		e, _, _ := newTestEvaluator(t, testNow, testBundle(t, testNow, 42, policies, nil), nil)
		// No Home set, so the ~/ glob is not renderable.
		got, err := e.EvaluateHarness(context.Background(), HarnessCall{Kind: "claude_code", Path: "/home/u/code/src/a.go"})
		if err != nil {
			t.Fatal(err)
		}
		if got.Outcome != policybundle.HarnessNotRenderable || got.PolicyID != "pol-1" || got.Reason != policybundle.HarnessReasonDstNotRenderable {
			t.Fatalf("got %+v", got)
		}
	})
}
