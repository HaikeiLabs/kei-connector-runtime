package pdp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

func newV2OwnerMCPEvaluator(t *testing.T, now time.Time, policy []any, approvedTools []any) (*Evaluator, string) {
	t.Helper()
	raw := v2GrantBundle(t, now, 1, nil, nil)
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	set := doc["policy_set"].(map[string]any)
	set["harness_match_semantics"] = "kei.harness-match/v1"
	set["harness_policies"] = policy
	set["connectors"] = []any{map[string]any{
		"id": "conn-linear", "name": "Linear", "provider": "linear_mcp", "credential_source": "oauth", "account_model": "shared", "capabilities": []any{},
		"kind": "mcp", "slug": "linear", "mcp": map[string]any{
			"url": "https://mcp.linear.example/mcp", "transport": "streamable_http", "auth_method": "oauth",
			"approved_manifest_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"approved_tools":         approvedTools,
		},
	}}
	doc["subject"] = map[string]any{"user_id": "u-alice", "email": "alice@example.test", "groups": []string{"members"}}
	doc["identities"] = []any{map[string]any{"source": "installation_owner", "external_id": "u-alice", "user_id": "u-alice", "status": "linked", "groups": []string{"members"}}}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	policybundle.SetV2SchemaValidator(func([]byte) error { return nil })
	t.Cleanup(func() { policybundle.SetV2SchemaValidator(nil) })
	sessions := NewSessions()
	sessionID, err := sessions.CreatePinned(Subject{UserID: "u-alice", Email: "alice@example.test", Source: "installation_owner", ExternalID: "u-alice", Status: StatusLinked, Groups: []string{"members"}})
	if err != nil {
		t.Fatal(err)
	}
	e, _, _ := newTestEvaluator(t, now, raw, sessions)
	return e, sessionID
}

func mcpHarnessPolicy(id, source, target, effect, harness string) any {
	return map[string]any{
		"policy_id": id, "name": id, "src_pattern": source, "dst_pattern": target, "action": effect, "priority": 10,
		"when":  map[string]any{"harness": harness},
		"scope": map[string]any{"org_id": testOrg, "workspace_id": testWorkspace, "agent_id": nil},
	}
}

func TestAuthorizeV2MCPUsesApprovedCanonicalTargets(t *testing.T) {
	now := time.Now().UTC()
	approved := []any{map[string]any{"name": "create_issue", "tool_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}
	tests := []struct {
		name      string
		policies  []any
		target    string
		harness   string
		approved  []any
		wantAllow bool
		wantCode  ReasonCode
	}{
		{name: "canonical permit", policies: []any{mcpHarnessPolicy("p-allow", "*", "mcp:linear.create_issue", "permit", "pi")}, target: "create_issue", harness: "pi", approved: approved, wantAllow: true, wantCode: "policy_permit"},
		{name: "canonical deny", policies: []any{mcpHarnessPolicy("p-deny", "*", "mcp:linear.create_issue", "deny", "pi")}, target: "create_issue", harness: "pi", approved: approved, wantCode: "policy_deny"},
		{name: "different harness", policies: []any{mcpHarnessPolicy("p-allow", "*", "mcp:linear.create_issue", "permit", "claude_code")}, target: "create_issue", harness: "pi", approved: approved, wantCode: "no_matching_policy"},
		{name: "unapproved method", policies: []any{mcpHarnessPolicy("p-allow", "*", "mcp:linear.delete_issue", "permit", "pi")}, target: "delete_issue", harness: "pi", approved: approved, wantCode: ReasonToolNotRegistered},
		{name: "missing approved manifest", policies: []any{mcpHarnessPolicy("p-allow", "*", "mcp:linear.create_issue", "permit", "pi")}, target: "create_issue", harness: "pi", approved: []any{}, wantCode: ReasonToolNotRegistered},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, sessionID := newV2OwnerMCPEvaluator(t, now, tc.policies, tc.approved)
			decision, err := e.AuthorizeV2MCP(context.Background(), sessionID, "linear", tc.target, testAgent, tc.harness)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Allow != tc.wantAllow || decision.ReasonCode != tc.wantCode {
				t.Fatalf("decision = %+v; want allow=%v reason=%q", decision, tc.wantAllow, tc.wantCode)
			}
		})
	}
}
