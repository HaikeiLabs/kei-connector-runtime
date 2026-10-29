package policybundle

import (
	"encoding/json"
	"testing"
	"time"
)

// denyOverridesBundle is a v2 harness bundle whose tool policies are replaced
// by rules and whose evaluation precedence is precedence.
func denyOverridesBundle(t *testing.T, now time.Time, precedence []string, rules ...[3]any) *Verified {
	t.Helper()
	v := v2HarnessBundle(t, now, "linked", "permit")
	var set map[string]any
	if err := json.Unmarshal(v.Payload.PolicySet, &set); err != nil {
		t.Fatal(err)
	}
	set["evaluation"].(map[string]any)["precedence"] = precedence
	policies := make([]any, 0, len(rules))
	for _, r := range rules {
		policies = append(policies, map[string]any{
			"policy_id": r[0], "name": r[0], "effect": r[1], "priority": r[2],
			"scope":    map[string]any{"org_id": "org-v2", "workspace_id": "ws-v2"},
			"selector": map[string]any{"source_principal": "user:user-alice", "source": "discord", "tool": "github.review_pr"},
		})
	}
	set["tool_policies"] = policies
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	v.Payload.PolicySet = raw
	return v
}

// Under deny_overrides any matching deny wins over every matching permit,
// priority is not read, and policy id ascending breaks ties. A bundle without
// it keeps the legacy order, where the highest priority decides (ADR-038 D-1,
// HAI-620).
func TestEvaluateV2DenyOverrides(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	subject := &SessionSubject{UserID: "user-alice", Source: "discord", ExternalID: "ext-alice", Status: SubjectLinked}
	legacy := []string{"priority_desc", "deny_before_permit", "policy_id_asc"}
	denyOverrides := []string{"deny_overrides"}
	for _, tc := range []struct {
		name       string
		precedence []string
		rules      [][3]any
		outcome    string
		policyID   string
	}{
		{"a low-priority deny beats a high-priority permit", denyOverrides, [][3]any{{"permit-hi", "permit", 100}, {"deny-lo", "deny", 1}}, "deny", "deny-lo"},
		{"legacy order lets the high-priority permit win", legacy, [][3]any{{"permit-hi", "permit", 100}, {"deny-lo", "deny", 1}}, "allow", "permit-hi"},
		{"priority is not read between permits", denyOverrides, [][3]any{{"b-permit", "permit", 100}, {"a-permit", "permit", 1}}, "allow", "a-permit"},
		{"legacy order reads priority between permits", legacy, [][3]any{{"b-permit", "permit", 100}, {"a-permit", "permit", 1}}, "allow", "b-permit"},
		{"policy id ascending breaks a deny tie", denyOverrides, [][3]any{{"b-deny", "deny", 1}, {"a-deny", "deny", 50}}, "deny", "a-deny"},
		{"a lone permit allows", denyOverrides, [][3]any{{"only", "permit", 0}}, "allow", "only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := denyOverridesBundle(t, now, tc.precedence, tc.rules...)
			d := v.EvaluateV2HarnessTool("github.review_pr", "", subject, now)
			if d.Outcome != tc.outcome || d.PolicyID != tc.policyID {
				t.Fatalf("decision = %+v, want %s by %s", d, tc.outcome, tc.policyID)
			}
			if tc.outcome == "deny" && d.ReasonCode != "policy_deny" {
				t.Fatalf("reason = %q, want policy_deny", d.ReasonCode)
			}
		})
	}
	t.Run("no matching rule still denies", func(t *testing.T) {
		v := denyOverridesBundle(t, now, denyOverrides)
		if d := v.EvaluateV2HarnessTool("github.review_pr", "", subject, now); d.Outcome != "deny" || d.ReasonCode != "no_matching_policy" {
			t.Fatalf("decision = %+v", d)
		}
	})
}
