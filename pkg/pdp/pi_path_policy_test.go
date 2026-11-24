package pdp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

func piPathPolicyBundle(t *testing.T, now time.Time, groups []string, toolPolicies, pathPolicies []any) []byte {
	t.Helper()
	raw := v2GrantBundle(t, now, 1, toolPolicies, nil)
	var bundle map[string]any
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatal(err)
	}
	set := bundle["policy_set"].(map[string]any)
	set["tools"] = []any{
		piFilesystemTool("pi.read", "read"),
		piFilesystemTool("pi.write", "write"),
		piFilesystemTool("pi.edit", "write"),
	}
	set["harness_policies"] = pathPolicies
	identity := bundle["identities"].([]any)[0].(map[string]any)
	identity["groups"] = groups
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func piFilesystemTool(name, operationClass string) any {
	return map[string]any{
		"name": name, "source": "pi", "operation_class": operationClass,
		"route": map[string]any{"harness_executor": map[string]any{"executor": "pi", "registration": name}},
	}
}

func pathPolicy(id, source, destination, action string, priority int) any {
	return map[string]any{
		"policy_id": id, "name": id, "src_pattern": source, "dst_pattern": destination,
		"action": action, "priority": priority,
		"scope": map[string]any{"org_id": testOrg, "workspace_id": testWorkspace, "agent_id": nil},
	}
}

func piFilesystemToolPermit(tool string) any {
	return map[string]any{
		"policy_id": "permit-" + tool, "name": "permit " + tool, "effect": "permit", "priority": 100,
		"scope":    map[string]any{"org_id": testOrg, "workspace_id": testWorkspace, "agent_id": nil},
		"selector": map[string]any{"source_principal": "group:bug-pr-bot", "tool": tool},
	}
}

func TestRegisteredPiReadAppliesGroupPathDenyAlongsideToolPermit(t *testing.T) {
	policybundle.SetV2SchemaValidator(func([]byte) error { return nil })
	t.Cleanup(func() { policybundle.SetV2SchemaValidator(nil) })
	now := time.Now().UTC()
	toolPolicies := []any{piFilesystemToolPermit("pi.read"), piFilesystemToolPermit("pi.write"), piFilesystemToolPermit("pi.edit")}
	tests := []struct {
		name       string
		tool       string
		resource   string
		pathPolicy any
		wantAllow  bool
		wantReason string
		wantPolicy string
	}{
		{"pi.read exact path deny", "pi.read", "/proc", pathPolicy("deny-proc", "group:bug-pr-bot", "path:/proc", "deny", 10), false, "policy_deny", "deny-proc"},
		{"pi.write descendant path deny", "pi.write", "/proc/fixture", pathPolicy("deny-proc-tree", "group:bug-pr-bot", "path:/proc/**", "deny", 10), false, "policy_deny", "deny-proc-tree"},
		{"pi.edit descendant path deny", "pi.edit", "/proc/fixture", pathPolicy("deny-proc-tree", "group:bug-pr-bot", "path:/proc/**", "deny", 10), false, "policy_deny", "deny-proc-tree"},
		{"unmatched path leaves the tool policy in force", "pi.read", "/tmp/fixture", pathPolicy("deny-proc-tree", "group:bug-pr-bot", "path:/proc/**", "deny", 10), true, "", "permit-pi.read"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bundle := piPathPolicyBundle(t, now, []string{"bug-pr-bot"}, toolPolicies, []any{tc.pathPolicy})
			e, sessionID := newV2GrantEvaluator(t, now, bundle, nil)
			result, err := e.Decide(context.Background(), DecideRequest{
				Session: sessionID, Target: Target{Tool: tc.tool, Resource: tc.resource}, TrustedAgent: testAgent,
			})
			decision := result.Decision
			if err != nil {
				t.Fatal(err)
			}
			if decision.Allow != tc.wantAllow || string(decision.ReasonCode) != tc.wantReason || decision.PolicyID != tc.wantPolicy {
				t.Fatalf("decision=%+v; want allow=%v reason=%q policy=%q", decision, tc.wantAllow, tc.wantReason, tc.wantPolicy)
			}
		})
	}
}

func TestRegisteredPiFilesystemToolRequiresCanonicalResourcePath(t *testing.T) {
	policybundle.SetV2SchemaValidator(func([]byte) error { return nil })
	t.Cleanup(func() { policybundle.SetV2SchemaValidator(nil) })
	now := time.Now().UTC()
	bundle := piPathPolicyBundle(t, now, []string{"bug-pr-bot"}, []any{piFilesystemToolPermit("pi.read")}, nil)
	e, sessionID := newV2GrantEvaluator(t, now, bundle, nil)
	for _, tc := range []struct{ resource, reason string }{
		{"", "resource_required"},
		{"relative/path", "invalid_resource_path"},
		{"/tmp/../proc", "invalid_resource_path"},
	} {
		result, err := e.Decide(context.Background(), DecideRequest{
			Session: sessionID, Target: Target{Tool: "pi.read", Resource: tc.resource}, TrustedAgent: testAgent,
		})
		decision := result.Decision
		if err != nil || decision.Allow || string(decision.ReasonCode) != tc.reason {
			t.Fatalf("resource=%q decision=%+v err=%v; want deny %q", tc.resource, decision, err, tc.reason)
		}
	}
}

func TestPiPathPermitDoesNotGrantRegisteredTool(t *testing.T) {
	policybundle.SetV2SchemaValidator(func([]byte) error { return nil })
	t.Cleanup(func() { policybundle.SetV2SchemaValidator(nil) })
	now := time.Now().UTC()
	bundle := piPathPolicyBundle(t, now, []string{"bug-pr-bot"}, nil, []any{
		pathPolicy("permit-temp", "group:bug-pr-bot", "path:/tmp/**", "permit", 10),
	})
	e, sessionID := newV2GrantEvaluator(t, now, bundle, nil)
	result, err := e.Decide(context.Background(), DecideRequest{
		Session: sessionID, Target: Target{Tool: "pi.read", Resource: "/tmp/fixture"}, TrustedAgent: testAgent,
	})
	decision := result.Decision
	if err != nil || decision.Allow || decision.ReasonCode != "no_matching_policy" {
		t.Fatalf("decision=%+v err=%v; path permit must not grant pi.read", decision, err)
	}
}
