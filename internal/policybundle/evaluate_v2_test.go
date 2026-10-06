package policybundle

import (
	"encoding/json"
	"testing"
	"time"
)

func v2ToolBundle(t *testing.T, now time.Time, checks []any) *Verified {
	t.Helper()
	doc := v2BundleDoc(now)
	doc["agent_connector_bindings"] = []any{map[string]any{"agent_id": "agent-a", "connector_id": "conn-a", "capabilities": []string{"pull_request.read", "check.read"}}}
	set := doc["policy_set"].(map[string]any)
	set["tools"] = []any{map[string]any{
		"name": "github.review_pr", "source": "github", "operation_class": "read",
		"route":                 map[string]any{"connector_binding": map[string]any{"connector_id": "conn-a"}},
		"required_capabilities": []string{"pull_request.read", "check.read"},
		"resource_types":        []any{map[string]any{"type": "pull_request", "parent_type": "repository"}},
	}}
	set["checks"] = checks
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return &Verified{Payload: func() Payload {
		var payload Payload
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatal(err)
		}
		return payload
	}(), PayloadBytes: raw, Digest: "sha256:test-v2"}
}

func v2Permit(policyID, capability string) any {
	return map[string]any{
		"policy_id": policyID, "name": policyID, "effect": "permit", "priority": 10,
		"scope":    map[string]any{"org_id": "org-v2", "workspace_id": "ws-v2", "agent_id": "agent-a"},
		"selector": map[string]any{"source_principal": "user:user-alice", "source": "github", "connector_id": "conn-a", "tool": "github.review_pr", "capability": capability, "resource_type": "pull_request", "resource_id": "42", "resource_parent": "repo:acme/project"},
	}
}

func TestEvaluateV2PlanRequiresANDForAllDeclaredCapabilities(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	subject := &SessionSubject{UserID: "user-alice", Source: "discord", ExternalID: "ext-alice", Status: SubjectLinked}
	ops := []Operation{
		{ConnectorID: "conn-a", Capability: "pull_request.read", Action: "read", Resource: "pull/42", ResourceType: "pull_request", ResourceID: "42", ResourceParent: "repo:acme/project", ResourceParentType: "repository"},
		{ConnectorID: "conn-a", Capability: "check.read", Action: "read", Resource: "pull/42", ResourceType: "pull_request", ResourceID: "42", ResourceParent: "repo:acme/project", ResourceParentType: "repository"},
	}
	t.Run("both permits allow", func(t *testing.T) {
		v := v2ToolBundle(t, now, []any{v2Permit("p1", "pull_request.read"), v2Permit("p2", "check.read")})
		if d := v.EvaluateV2Plan("github.review_pr", "agent-a", subject, ops, now); d.Outcome != "allow" {
			t.Fatalf("decision = %+v", d)
		}
	})
	t.Run("missing capability check denies", func(t *testing.T) {
		v := v2ToolBundle(t, now, []any{v2Permit("p1", "pull_request.read")})
		if d := v.EvaluateV2Plan("github.review_pr", "agent-a", subject, ops, now); d.Outcome != "deny" {
			t.Fatalf("decision = %+v", d)
		}
	})
	for name, mutate := range map[string]func([]Operation){
		"extra capability":       func(plan []Operation) { plan[1].Capability = "secret.write" },
		"parent type mismatch":   func(plan []Operation) { plan[0].ResourceParentType = "organization" },
		"missing parent context": func(plan []Operation) { plan[0].ResourceParent = "" },
	} {
		t.Run(name, func(t *testing.T) {
			v := v2ToolBundle(t, now, []any{v2Permit("p1", "pull_request.read"), v2Permit("p2", "check.read")})
			plan := append([]Operation(nil), ops...)
			mutate(plan)
			if d := v.EvaluateV2Plan("github.review_pr", "agent-a", subject, plan, now); d.Outcome != "deny" || d.ReasonCode != "operation_plan_invalid" {
				t.Fatalf("decision = %+v", d)
			}
		})
	}
	t.Run("resource id mismatch is denied by structured selector", func(t *testing.T) {
		v := v2ToolBundle(t, now, []any{v2Permit("p1", "pull_request.read"), v2Permit("p2", "check.read")})
		plan := append([]Operation(nil), ops...)
		plan[0].ResourceID = "43"
		if d := v.EvaluateV2Plan("github.review_pr", "agent-a", subject, plan, now); d.Outcome != "deny" || d.ReasonCode != "no_matching_policy" {
			t.Fatalf("resource id mismatch decision=%+v", d)
		}
	})
	t.Run("parent mismatch is denied by structured selector", func(t *testing.T) {
		v := v2ToolBundle(t, now, []any{v2Permit("p1", "pull_request.read"), v2Permit("p2", "check.read")})
		plan := append([]Operation(nil), ops...)
		plan[0].ResourceParent = "repo:acme/other"
		if d := v.EvaluateV2Plan("github.review_pr", "agent-a", subject, plan, now); d.Outcome != "deny" || d.ReasonCode != "no_matching_policy" {
			t.Fatalf("parent mismatch decision=%+v", d)
		}
	})
}

func TestV2DirectCapabilityPermitDoesNotImplyToolPermit(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	v := v2ToolBundle(t, now, []any{
		map[string]any{"policy_id": "direct-read", "name": "direct", "effect": "permit", "priority": 100, "scope": map[string]any{"org_id": "org-v2", "workspace_id": "ws-v2", "agent_id": "agent-a"}, "selector": map[string]any{"source_principal": "user:user-alice", "capability": "pull_request.read"}},
		map[string]any{"policy_id": "direct-check", "name": "direct", "effect": "permit", "priority": 100, "scope": map[string]any{"org_id": "org-v2", "workspace_id": "ws-v2", "agent_id": "agent-a"}, "selector": map[string]any{"source_principal": "user:user-alice", "capability": "check.read"}},
	})
	subject := &SessionSubject{UserID: "user-alice", Source: "discord", ExternalID: "ext-alice", Status: SubjectLinked}
	ops := []Operation{{ConnectorID: "conn-a", Capability: "pull_request.read", Action: "read", Resource: "pull/42", ResourceType: "pull_request", ResourceID: "42", ResourceParent: "repo:acme/project", ResourceParentType: "repository"}, {ConnectorID: "conn-a", Capability: "check.read", Action: "read", Resource: "pull/42", ResourceType: "pull_request", ResourceID: "42", ResourceParent: "repo:acme/project", ResourceParentType: "repository"}}
	if d := v.EvaluateV2Plan("github.review_pr", "agent-a", subject, ops, now); d.Outcome != "deny" {
		t.Fatalf("direct capability permits authorized tool call: %+v", d)
	}
}

func TestEvaluateV2PlanDeniesExpiredSnapshotAndRefreshSubstitution(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	v := v2ToolBundle(t, now, []any{v2Permit("p1", "pull_request.read"), v2Permit("p2", "check.read")})
	subject := &SessionSubject{UserID: "user-alice", Source: "discord", ExternalID: "ext-alice", Status: SubjectLinked}
	ops := []Operation{{ConnectorID: "conn-a", Capability: "pull_request.read", Action: "read", Resource: "pull/42", ResourceType: "pull_request", ResourceID: "42", ResourceParent: "repo:acme/project", ResourceParentType: "repository"}, {ConnectorID: "conn-a", Capability: "check.read", Action: "read", Resource: "pull/42", ResourceType: "pull_request", ResourceID: "42", ResourceParent: "repo:acme/project", ResourceParentType: "repository"}}
	if d := v.EvaluateV2Plan("github.review_pr", "agent-a", subject, ops, now.Add(30*time.Second)); d.ReasonCode != "subject_snapshot_stale" {
		t.Fatalf("stale decision = %+v", d)
	}
	v.Payload.Identities[0].ExternalID = "changed-identity"
	if d := v.EvaluateV2Plan("github.review_pr", "agent-a", subject, ops, now); d.ReasonCode != "subject_unlinked" {
		t.Fatalf("substituted identity decision = %+v", d)
	}
}

func TestV2SessionPathRequiresPreflight(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	v := v2ToolBundle(t, now, nil)
	d := v.EvaluateSessionAt(Call{Tool: "github.review_pr"}, &SessionSubject{UserID: "user-alice", Source: "discord", ExternalID: "ext-alice", Status: SubjectLinked}, nil, now)
	if d.Outcome != "deny" || d.ReasonCode != "preflight_required" {
		t.Fatalf("v2 regular authorize path = %+v", d)
	}
}
