package policybundle

import (
	"encoding/json"
	"testing"
	"time"
)

// v2GrantBundle is a v2 bundle with one registered harness tool, the given
// tool policies and the given access grants. The grants sit next to the
// bundle, not inside the policy set: the catalog projects the workspace's
// live grants into the v2 envelope (ADR-038, HAI-615).
func v2GrantBundle(t *testing.T, now time.Time, toolPolicies []any, grants []any) *Verified {
	t.Helper()
	doc := v2BundleDoc(now)
	set := doc["policy_set"].(map[string]any)
	set["tools"] = []any{map[string]any{
		"name": "web_search", "source": "web", "operation_class": "read",
		"route": map[string]any{"harness_executor": map[string]any{"executor": "harness", "registration": "web_search"}},
	}}
	set["tool_policies"] = toolPolicies
	if grants != nil {
		doc["access_grants"] = grants
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var payload Payload
	if err := strictJSON(raw, &payload); err != nil {
		t.Fatalf("decode v2 bundle with access grants: %v", err)
	}
	return &Verified{Payload: payload, PayloadBytes: raw, Digest: "sha256:test-v2-grants"}
}

// v2GrantSubject is the session subject the v2 grant bundle's identity
// carries: user-alice, linked, in group members.
func v2GrantSubject() *SessionSubject {
	return &SessionSubject{UserID: "user-alice", Source: "discord", ExternalID: "ext-alice", Status: SubjectLinked}
}

// v2LiveGrant is an access grant that is live for the next hour.
func v2LiveGrant(now time.Time, principal, target string) any {
	return map[string]any{"principal": principal, "target": target, "expire_time": now.Add(time.Hour).Format(time.RFC3339)}
}

// v2ExpiredGrant is an access grant that ended a minute ago.
func v2ExpiredGrant(now time.Time, principal, target string) any {
	return map[string]any{"principal": principal, "target": target, "expire_time": now.Add(-time.Minute).Format(time.RFC3339)}
}

// v2DenyToolPolicy is a tool policy that denies one tool for one principal.
func v2DenyToolPolicy(principal, tool string) any {
	return map[string]any{
		"policy_id": "pol-deny-web-search", "name": "deny " + tool, "effect": "deny", "priority": 100,
		"scope":    map[string]any{"org_id": "org-v2", "workspace_id": "ws-v2", "agent_id": nil},
		"selector": map[string]any{"source_principal": principal, "tool": tool},
	}
}

// v2PlanGrantBundle is a v2 bundle with the connector tool and the given
// checks, carrying the given access grants.
func v2PlanGrantBundle(t *testing.T, now time.Time, checks []any, grants []any) *Verified {
	t.Helper()
	v := v2ToolBundle(t, now, checks)
	var doc map[string]any
	if err := json.Unmarshal(v.PayloadBytes, &doc); err != nil {
		t.Fatal(err)
	}
	if grants != nil {
		doc["access_grants"] = grants
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var payload Payload
	if err := strictJSON(raw, &payload); err != nil {
		t.Fatalf("decode v2 bundle with access grants: %v", err)
	}
	return &Verified{Payload: payload, PayloadBytes: raw, Digest: "sha256:test-v2-plan-grants"}
}

// TestV2AccessGrantPermitsACallNoRuleCovers proves a live access grant opens
// a call that no rule in the bundle covers (ADR-038 §2): the grant is the
// only thing that permits it.
func TestV2AccessGrantPermitsACallNoRuleCovers(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	v := v2GrantBundle(t, now, nil, []any{v2LiveGrant(now, "user:user-alice", "tool:web_search")})
	decision := v.EvaluateV2HarnessTool("web_search", "agent-a", v2GrantSubject(), now)
	if decision.Outcome != "allow" {
		t.Fatalf("decision=%+v, want allow from the live access grant", decision)
	}
}

// TestV2AccessGrantExpiredDeniesWithAccessGrantExpired proves an expired
// grant denies with the shared policy package's reason, and never permits.
func TestV2AccessGrantExpiredDeniesWithAccessGrantExpired(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	v := v2GrantBundle(t, now, nil, []any{v2ExpiredGrant(now, "user:user-alice", "tool:web_search")})
	decision := v.EvaluateV2HarnessTool("web_search", "agent-a", v2GrantSubject(), now)
	if decision.Outcome != "deny" || decision.ReasonCode != "access_grant_expired" {
		t.Fatalf("decision=%+v, want deny with access_grant_expired", decision)
	}
}

// TestV2AccessGrantDenyRuleStillWins proves a matching deny rule is never
// overridden by a live access grant (ADR-038 D-1: deny always wins).
func TestV2AccessGrantDenyRuleStillWins(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	policies := []any{v2DenyToolPolicy("user:user-alice", "web_search")}
	v := v2GrantBundle(t, now, policies, []any{v2LiveGrant(now, "user:user-alice", "tool:web_search")})
	decision := v.EvaluateV2HarnessTool("web_search", "agent-a", v2GrantSubject(), now)
	if decision.Outcome != "deny" || decision.ReasonCode != "policy_deny" {
		t.Fatalf("decision=%+v, want deny with policy_deny", decision)
	}
}

// TestV2AccessGrantWithNoGrantMatchedDeniesWithNoGrantMatched proves a
// bundle that carries grants reports the shared package's reason when none
// of them covers the call.
func TestV2AccessGrantWithNoGrantMatchedDeniesWithNoGrantMatched(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	grants := []any{
		v2LiveGrant(now, "user:someone-else", "tool:web_search"),
		v2LiveGrant(now, "user:user-alice", "tool:other_tool"),
	}
	v := v2GrantBundle(t, now, nil, grants)
	decision := v.EvaluateV2HarnessTool("web_search", "agent-a", v2GrantSubject(), now)
	if decision.Outcome != "deny" || decision.ReasonCode != "no_grant_matched" {
		t.Fatalf("decision=%+v, want deny with no_grant_matched", decision)
	}
}

// TestV2BundleWithoutAccessGrantsDecisionsUnchanged proves a bundle that
// carries no grant decides exactly as it did before grants existed: the
// runtime's own no_matching_policy deny, with no grant reason in sight.
func TestV2BundleWithoutAccessGrantsDecisionsUnchanged(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	v := v2GrantBundle(t, now, nil, nil)
	decision := v.EvaluateV2HarnessTool("web_search", "agent-a", v2GrantSubject(), now)
	if decision.Outcome != "deny" || decision.ReasonCode != "no_matching_policy" {
		t.Fatalf("decision=%+v, want deny with no_matching_policy", decision)
	}
}

// TestV2AccessGrantUsesBundleGroupsOnly proves the groups a decision uses are
// the bundle's, never the session's (B-20). The bundle's identity carries
// group members only, so a grant for another group opens nothing, and a grant
// for the group the bundle carries opens the call.
func TestV2AccessGrantUsesBundleGroupsOnly(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	grants := []any{v2LiveGrant(now, "group:release_eng", "tool:web_search")}
	v := v2GrantBundle(t, now, nil, grants)
	decision := v.EvaluateV2HarnessTool("web_search", "agent-a", v2GrantSubject(), now)
	if decision.Outcome != "deny" {
		t.Fatalf("decision=%+v, want deny: the bundle carries no release_eng group", decision)
	}
	grants = []any{v2LiveGrant(now, "group:members", "tool:web_search")}
	v = v2GrantBundle(t, now, nil, grants)
	decision = v.EvaluateV2HarnessTool("web_search", "agent-a", v2GrantSubject(), now)
	if decision.Outcome != "allow" {
		t.Fatalf("decision=%+v, want allow: the bundle carries the members group", decision)
	}
}

// TestV2AccessGrantOnlyAppliesToItsOwnTarget proves a grant opens the target
// it names and nothing else (ADR-038 §2: matching is exact).
func TestV2AccessGrantOnlyAppliesToItsOwnTarget(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	v := v2GrantBundle(t, now, nil, []any{v2LiveGrant(now, "user:user-alice", "tool:web_search_admin")})
	decision := v.EvaluateV2HarnessTool("web_search", "agent-a", v2GrantSubject(), now)
	if decision.Outcome != "deny" || decision.ReasonCode != "no_grant_matched" {
		t.Fatalf("decision=%+v, want deny with no_grant_matched", decision)
	}
}

// TestV2AccessGrantPermitsAConnectorPlanNoRuleCovers proves a live access
// grant opens a connector plan that no check in the bundle covers. The grant
// is decided at the tool's level, so it covers the tool's capabilities.
func TestV2AccessGrantPermitsAConnectorPlanNoRuleCovers(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	v := v2PlanGrantBundle(t, now, nil, []any{v2LiveGrant(now, "user:user-alice", "tool:github.review_pr")})
	decision := v.EvaluateV2Plan("github.review_pr", "agent-a", v2GrantSubject(), v2TestPlanOps(), now)
	if decision.Outcome != "allow" {
		t.Fatalf("decision=%+v, want allow from the live access grant", decision)
	}
}

// TestV2AccessGrantExpiredDeniesAConnectorPlan proves an expired grant denies
// a connector plan with the shared policy package's reason.
func TestV2AccessGrantExpiredDeniesAConnectorPlan(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	v := v2PlanGrantBundle(t, now, nil, []any{v2ExpiredGrant(now, "user:user-alice", "tool:github.review_pr")})
	decision := v.EvaluateV2Plan("github.review_pr", "agent-a", v2GrantSubject(), v2TestPlanOps(), now)
	if decision.Outcome != "deny" || decision.ReasonCode != "access_grant_expired" {
		t.Fatalf("decision=%+v, want deny with access_grant_expired", decision)
	}
}

// TestV2AccessGrantDenyRuleStillWinsOverAConnectorPlan proves a matching deny
// check is never overridden by a live access grant (ADR-038 D-1).
func TestV2AccessGrantDenyRuleStillWinsOverAConnectorPlan(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	deny := map[string]any{
		"policy_id": "p-deny", "name": "deny", "effect": "deny", "priority": 100,
		"scope":    map[string]any{"org_id": "org-v2", "workspace_id": "ws-v2", "agent_id": "agent-a"},
		"selector": map[string]any{"source_principal": "user:user-alice", "source": "github", "connector_id": "conn-a", "tool": "github.review_pr", "capability": "pull_request.read", "resource_type": "pull_request", "resource_id": "42", "resource_parent": "acme/project"},
	}
	v := v2PlanGrantBundle(t, now, []any{deny}, []any{v2LiveGrant(now, "user:user-alice", "tool:github.review_pr")})
	decision := v.EvaluateV2Plan("github.review_pr", "agent-a", v2GrantSubject(), v2TestPlanOps(), now)
	if decision.Outcome != "deny" || decision.ReasonCode != "policy_deny" {
		t.Fatalf("decision=%+v, want deny with policy_deny", decision)
	}
}

// TestValidateV2AcceptsAccessGrants proves the closed v2 contract accepts the
// access_grants projection the catalog emits (ADR-038, HAI-615) and that the
// grants are decoded: a bundle that carries them is usable, not invalid.
func TestValidateV2AcceptsAccessGrants(t *testing.T) {
	previous := schemaValidatorV2
	SetV2SchemaValidator(v2SchemaValidator(t))
	t.Cleanup(func() { SetV2SchemaValidator(previous) })
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	doc := v2BundleDoc(now)
	doc["access_grants"] = []any{map[string]any{
		"principal": "user:user-alice", "target": "tool:web_search",
		"expire_time": now.Add(time.Hour).Format(time.RFC3339),
	}}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	v, err := ValidateV2(raw, v2Installation, v2Org, v2Workspace, 1, now)
	if err != nil {
		t.Fatalf("ValidateV2 rejected a bundle with access grants: %v", err)
	}
	if len(v.Payload.AccessGrants) != 1 {
		t.Fatalf("decoded grants=%#v, want the one the bundle carries", v.Payload.AccessGrants)
	}
	grant := v.Payload.AccessGrants[0]
	if grant.Principal != "user:user-alice" || grant.Target != "tool:web_search" || !grant.ExpireTime.Equal(now.Add(time.Hour)) {
		t.Fatalf("decoded grant=%+v, want the principal, target and expiry the bundle carries", grant)
	}
}

// TestValidateV2RejectsMalformedAccessGrant proves a grant is read as the
// closed contract it is: it carries a principal, a target and an expiry, and
// nothing else.
func TestValidateV2RejectsMalformedAccessGrant(t *testing.T) {
	previous := schemaValidatorV2
	SetV2SchemaValidator(v2SchemaValidator(t))
	t.Cleanup(func() { SetV2SchemaValidator(previous) })
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	marshal := func(grant map[string]any) []byte {
		t.Helper()
		doc := v2BundleDoc(now)
		doc["access_grants"] = []any{grant}
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	valid := map[string]any{"principal": "user:user-alice", "target": "tool:web_search", "expire_time": now.Add(time.Hour).Format(time.RFC3339)}
	if _, err := ValidateV2(marshal(valid), v2Installation, v2Org, v2Workspace, 1, now); err != nil {
		t.Fatalf("ValidateV2 rejected a well-formed grant: %v", err)
	}
	withoutExpiry := map[string]any{"principal": "user:user-alice", "target": "tool:web_search"}
	if _, err := ValidateV2(marshal(withoutExpiry), v2Installation, v2Org, v2Workspace, 1, now); err == nil {
		t.Fatal("accepted a grant without an expiry")
	}
	widened := map[string]any{"principal": "user:user-alice", "target": "tool:web_search", "expire_time": now.Add(time.Hour).Format(time.RFC3339), "reason": "why the grant exists"}
	if _, err := ValidateV2(marshal(widened), v2Installation, v2Org, v2Workspace, 1, now); err == nil {
		t.Fatal("accepted a grant carrying a field outside the contract")
	}
}
