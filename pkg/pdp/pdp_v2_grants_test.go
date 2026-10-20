package pdp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

// v2GrantBundle is a v2 bundle with one registered harness tool, the given
// tool policies and the given access grants. The grants sit next to the
// bundle, not inside the policy set: the catalog projects the workspace's
// live grants into the v2 envelope (ADR-038, HAI-615).
func v2GrantBundle(t *testing.T, now time.Time, version int64, toolPolicies []any, grants []any) []byte {
	t.Helper()
	bundle := map[string]any{
		"schema": "kei.policy-bundle/v2", "bundle_id": "bundle-v2-grants", "bundle_version": version, "policy_revision": 1, "issuer": policybundle.Issuer,
		"audience":  map[string]any{"installation_id": testInstallation, "org_id": testOrg, "workspace_id": testWorkspace},
		"issued_at": now.UTC().Format(time.RFC3339Nano), "not_after": now.Add(12 * time.Hour).UTC().Format(time.RFC3339Nano),
		"refresh":            map[string]any{"poll_interval_seconds": 60, "stale_after_seconds": 300},
		"subject_resolution": map[string]any{"mode": "bundle", "max_cache_seconds": 1},
		"policy_set": map[string]any{
			"schema": "kei.policy-set/v2", "org_id": testOrg, "workspace_id": testWorkspace, "match_semantics": "kei.match/v2",
			"evaluation": map[string]any{"precedence": []string{"priority_desc", "deny_before_permit", "policy_id_asc"}, "checks": "per_capability_first_match_and", "default": "deny"},
			"tools": []any{map[string]any{
				"name": "web_search", "source": "web", "operation_class": "read",
				"route": map[string]any{"harness_executor": map[string]any{"executor": "harness", "registration": "web_search"}},
			}},
			"checks": []any{}, "tool_policies": toolPolicies,
			"harness_match_semantics": "kei.harness-match/v1", "harness_policies": []any{},
		},
		"agent_connector_bindings": []any{},
		"identities":               []any{map[string]any{"source": "discord", "external_id": "discord-old", "user_id": "u-alice", "status": "linked", "groups": []string{"members"}}},
	}
	if grants != nil {
		bundle["access_grants"] = grants
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// v2Grant is an access grant that stays live for the next hour.
func v2Grant(now time.Time, principal, target string) any {
	return map[string]any{"principal": principal, "target": target, "expire_time": now.Add(time.Hour).Format(time.RFC3339)}
}

// v2GrantDenyPolicy is a tool policy that denies one tool for one principal.
func v2GrantDenyPolicy(principal, tool string) any {
	return map[string]any{
		"policy_id": "pol-deny-web-search", "name": "deny " + tool, "effect": "deny", "priority": 100,
		"scope":    map[string]any{"org_id": testOrg, "workspace_id": testWorkspace, "agent_id": nil},
		"selector": map[string]any{"source_principal": principal, "tool": tool},
	}
}

// v2GrantPermitPolicy is a tool policy that permits one tool for one
// principal.
func v2GrantPermitPolicy(principal, tool string) any {
	return map[string]any{
		"policy_id": "pol-permit-web-search", "name": "permit " + tool, "effect": "permit", "priority": 100,
		"scope":    map[string]any{"org_id": testOrg, "workspace_id": testWorkspace, "agent_id": nil},
		"selector": map[string]any{"source_principal": principal, "tool": tool},
	}
}

// newV2GrantEvaluator activates a v2 grant bundle and returns an evaluator
// whose clock is the given time, with one linked session for u-alice.
func newV2GrantEvaluator(t *testing.T, now time.Time, bundle []byte, groups []string) (*Evaluator, string) {
	t.Helper()
	policybundle.SetV2SchemaValidator(func([]byte) error { return nil })
	t.Cleanup(func() { policybundle.SetV2SchemaValidator(nil) })
	sessions := NewSessions()
	sessionID, err := sessions.Create(Subject{UserID: "u-alice", Source: "discord", ExternalID: "discord-old", Status: StatusLinked, Groups: groups})
	if err != nil {
		t.Fatal(err)
	}
	e, _, _ := newTestEvaluator(t, now, bundle, sessions)
	return e, sessionID
}

// TestAuthorizeV2HarnessToolAllowsLiveAccessGrant proves a live access grant
// opens a harness tool call that no rule in the bundle covers.
func TestAuthorizeV2HarnessToolAllowsLiveAccessGrant(t *testing.T) {
	now := time.Now().UTC()
	bundle := v2GrantBundle(t, now, 1, nil, []any{v2Grant(now, "user:u-alice", "tool:web_search")})
	e, sessionID := newV2GrantEvaluator(t, now, bundle, nil)
	decision, err := e.AuthorizeV2HarnessTool(context.Background(), Request{Session: sessionID, Tool: "web_search", AgentID: testAgent})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allow {
		t.Fatalf("decision=%+v, want allow from the live access grant", decision)
	}
}

// TestAuthorizeV2HarnessToolDeniesExpiredAccessGrant proves an expired grant
// denies with the shared policy package's reason and never permits.
func TestAuthorizeV2HarnessToolDeniesExpiredAccessGrant(t *testing.T) {
	now := time.Now().UTC()
	expired := map[string]any{"principal": "user:u-alice", "target": "tool:web_search", "expire_time": now.Add(-time.Minute).Format(time.RFC3339)}
	bundle := v2GrantBundle(t, now, 1, nil, []any{expired})
	e, sessionID := newV2GrantEvaluator(t, now, bundle, nil)
	decision, err := e.AuthorizeV2HarnessTool(context.Background(), Request{Session: sessionID, Tool: "web_search", AgentID: testAgent})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allow || decision.ReasonCode != "access_grant_expired" {
		t.Fatalf("decision=%+v, want deny with access_grant_expired", decision)
	}
}

// TestAuthorizeV2HarnessToolDenyRuleBeatsLiveGrant proves a matching deny
// rule is never overridden by a live access grant (ADR-038 D-1).
func TestAuthorizeV2HarnessToolDenyRuleBeatsLiveGrant(t *testing.T) {
	now := time.Now().UTC()
	policies := []any{v2GrantDenyPolicy("user:u-alice", "web_search")}
	bundle := v2GrantBundle(t, now, 1, policies, []any{v2Grant(now, "user:u-alice", "tool:web_search")})
	e, sessionID := newV2GrantEvaluator(t, now, bundle, nil)
	decision, err := e.AuthorizeV2HarnessTool(context.Background(), Request{Session: sessionID, Tool: "web_search", AgentID: testAgent})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allow || decision.ReasonCode != "policy_deny" {
		t.Fatalf("decision=%+v, want deny with policy_deny", decision)
	}
}

// TestAuthorizeV2HarnessToolWithoutAccessGrantsIsUnchanged proves a bundle
// that carries no grant decides exactly as it did before grants existed.
func TestAuthorizeV2HarnessToolWithoutAccessGrantsIsUnchanged(t *testing.T) {
	now := time.Now().UTC()
	bundle := v2GrantBundle(t, now, 1, nil, nil)
	e, sessionID := newV2GrantEvaluator(t, now, bundle, nil)
	decision, err := e.AuthorizeV2HarnessTool(context.Background(), Request{Session: sessionID, Tool: "web_search", AgentID: testAgent})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allow || decision.ReasonCode != "no_matching_policy" {
		t.Fatalf("decision=%+v, want deny with no_matching_policy", decision)
	}
}

// TestAccessGrantExpiryFollowsTheEvaluatorClock proves the grant's expiry is
// read against the runtime's own clock: the same bundle permits before the
// expiry and denies after it.
func TestAccessGrantExpiryFollowsTheEvaluatorClock(t *testing.T) {
	now := time.Now().UTC()
	bundle := v2GrantBundle(t, now, 1, nil, []any{v2Grant(now, "user:u-alice", "tool:web_search")})
	e, sessionID := newV2GrantEvaluator(t, now, bundle, nil)
	request := Request{Session: sessionID, Tool: "web_search", AgentID: testAgent}
	decision, err := e.AuthorizeV2HarnessTool(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allow {
		t.Fatalf("decision=%+v, want allow before the grant expires", decision)
	}
	e.now = func() time.Time { return now.Add(2 * time.Hour) }
	decision, err = e.AuthorizeV2HarnessTool(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allow || decision.ReasonCode != "access_grant_expired" {
		t.Fatalf("decision=%+v, want deny with access_grant_expired after the grant expires", decision)
	}
}

// TestV2DecisionIgnoresSessionGroups proves the groups a decision uses are
// the bundle's, never the session's (B-20). The session claims a group the
// bundle does not carry, so the rule that names it does not match and the
// call is denied.
func TestV2DecisionIgnoresSessionGroups(t *testing.T) {
	now := time.Now().UTC()
	policies := []any{v2GrantPermitPolicy("group:release_eng", "web_search")}
	bundle := v2GrantBundle(t, now, 1, policies, nil)
	e, sessionID := newV2GrantEvaluator(t, now, bundle, []string{"release_eng"})
	decision, err := e.AuthorizeV2HarnessTool(context.Background(), Request{Session: sessionID, Tool: "web_search", AgentID: testAgent})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allow {
		t.Fatalf("decision=%+v, want deny: the bundle carries no release_eng group", decision)
	}
}
