package policybundle

import (
	"testing"
	"time"
)

// whenPolicy is one harness_policies row for the D-6 tests; when is the harness
// kind of its when {harness} condition, empty for none.
type whenPolicy struct {
	id, src, dst, action, when string
}

func whenBundle(t *testing.T, now time.Time, precedence []string, policies ...whenPolicy) *Verified {
	t.Helper()
	previous := schemaValidatorV2
	SetV2SchemaValidator(v2SchemaValidator(t))
	t.Cleanup(func() { SetV2SchemaValidator(previous) })
	doc := v2BundleDoc(now)
	set := doc["policy_set"].(map[string]any)
	if precedence != nil {
		set["evaluation"].(map[string]any)["precedence"] = precedence
	}
	rows := make([]any, 0, len(policies))
	for _, p := range policies {
		row := map[string]any{
			"policy_id": p.id, "name": p.id, "src_pattern": p.src, "dst_pattern": p.dst, "action": p.action, "priority": 0,
			"scope": map[string]any{"org_id": v2Org, "workspace_id": v2Workspace, "agent_id": nil},
		}
		if p.when != "" {
			row["when"] = map[string]any{"harness": p.when}
		}
		rows = append(rows, row)
	}
	set["harness_policies"] = rows
	v, err := ValidateV2(mustJSON(t, doc), v2Installation, v2Org, v2Workspace, 1, now)
	if err != nil {
		t.Fatalf("ValidateV2 with when: %v", err)
	}
	return v
}

// A harness policy with a when {harness} condition applies only to calls made
// through that kind, on every path the runtime decides harness calls
// (ADR-038 D-6): the kei.harness-match/v1 evaluator, MCP and shell.
func TestWhenHarnessScopesRulesOnEveryPath(t *testing.T) {
	now := time.Now().UTC()
	denyOverrides := []string{"deny_overrides"}
	subject := &SessionSubject{UserID: "user-alice", Source: "discord", ExternalID: "ext-alice", Status: SubjectLinked}

	t.Run("EvaluateHarness", func(t *testing.T) {
		v := whenBundle(t, now, denyOverrides, whenPolicy{"p-codex", "*", "shell:git", "permit", "codex"})
		if outcome, id, _ := v.EvaluateHarness(HarnessCall{Kind: "codex", Argv: []string{"git", "status"}}); outcome != HarnessPermit || id != "p-codex" {
			t.Fatalf("matching kind = %q, %q, want permit by p-codex", outcome, id)
		}
		if outcome, _, _ := v.EvaluateHarness(HarnessCall{Kind: "claude_code", Argv: []string{"git", "status"}}); outcome == HarnessPermit {
			t.Fatalf("other kind permitted by a rule scoped to codex")
		}
		if outcome, _, _ := v.EvaluateHarness(HarnessCall{Argv: []string{"git", "status"}}); outcome == HarnessPermit {
			t.Fatalf("unknown kind permitted by a rule scoped to codex")
		}
	})

	t.Run("EvaluateHarness a deny whose when does not match does not apply", func(t *testing.T) {
		v := whenBundle(t, now, denyOverrides,
			whenPolicy{"p-permit", "*", "shell:git", "permit", ""},
			whenPolicy{"p-deny-codex", "*", "shell:git", "deny", "codex"})
		if outcome, id, _ := v.EvaluateHarness(HarnessCall{Kind: "claude_code", Argv: []string{"git", "status"}}); outcome != HarnessPermit || id != "p-permit" {
			t.Fatalf("claude_code = %q, %q, want permit by p-permit", outcome, id)
		}
		if outcome, id, _ := v.EvaluateHarness(HarnessCall{Kind: "codex", Argv: []string{"git", "status"}}); outcome != HarnessDeny || id != "p-deny-codex" {
			t.Fatalf("codex = %q, %q, want deny by p-deny-codex", outcome, id)
		}
	})

	t.Run("MCP composes with deny-overrides", func(t *testing.T) {
		v := whenBundle(t, now, denyOverrides,
			whenPolicy{"p-permit", "*", "mcp:slack", "permit", ""},
			whenPolicy{"p-deny-codex", "*", "mcp:slack.list_channels", "deny", "codex"})
		if d := v.EvaluateV2MCP("slack", "list_channels", "agent-a", "codex", subject, now); d.Outcome != "deny" || d.PolicyID != "p-deny-codex" {
			t.Fatalf("codex = %+v, want deny by p-deny-codex", d)
		}
		if d := v.EvaluateV2MCP("slack", "list_channels", "agent-a", "claude_code", subject, now); d.Outcome != "allow" || d.PolicyID != "p-permit" {
			t.Fatalf("claude_code = %+v, want allow by p-permit", d)
		}
	})

	t.Run("MCP permit with a when fails closed for another kind", func(t *testing.T) {
		v := whenBundle(t, now, denyOverrides, whenPolicy{"p-codex", "*", "mcp:slack", "permit", "codex"})
		if d := v.EvaluateV2MCP("slack", "list_channels", "agent-a", "claude_code", subject, now); d.Outcome != "deny" || d.ReasonCode != "no_matching_policy" {
			t.Fatalf("claude_code = %+v, want deny no_matching_policy", d)
		}
	})

	t.Run("shell decides for pi", func(t *testing.T) {
		v := whenBundle(t, now, denyOverrides,
			whenPolicy{"p-permit", "*", "shell:git", "permit", ""},
			whenPolicy{"p-deny-pi", "*", "shell:git", "deny", "pi"},
			whenPolicy{"p-deny-codex", "*", "shell:ls", "deny", "codex"})
		if d := v.EvaluateV2Shell([]string{"git", "status"}, "agent-a", subject, now); d.Outcome != "deny" || d.PolicyID != "p-deny-pi" {
			t.Fatalf("git = %+v, want deny by p-deny-pi", d)
		}
		if d := v.EvaluateV2Shell([]string{"ls"}, "agent-a", subject, now); d.PolicyID == "p-deny-codex" {
			t.Fatalf("ls = %+v, a rule scoped to codex applied to pi", d)
		}
	})
}
