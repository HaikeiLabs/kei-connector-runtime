package policybundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

// opGrantBundle builds a catalog-shaped v2 bundle whose connector tool
// registrations mirror the opsproof demo: three tools bound to conn-a whose
// operations carry the operation-id capabilities github.issues.get and
// github.issues.list (read) and github.issues.create (write), plus a harness
// executor tool. The checks, tool policies and access grants come from the
// caller so each test pins one rule shape.
func opGrantBundle(t *testing.T, now time.Time, checks, toolPolicies, grants []any) *Verified {
	t.Helper()
	previous := schemaValidatorV2
	SetV2SchemaValidator(v2SchemaValidator(t))
	t.Cleanup(func() { SetV2SchemaValidator(previous) })

	doc := v2BundleDoc(now)
	doc["agent_connector_bindings"] = []any{map[string]any{"agent_id": "agent-a", "connector_id": "conn-a", "capabilities": []string{"github.issues.get", "github.issues.list", "github.issues.create"}}}
	if grants != nil {
		doc["access_grants"] = grants
	}
	doc["identities"] = []any{
		map[string]any{"source": "discord", "external_id": "ext-alice", "user_id": "user-alice", "status": "linked", "groups": []string{"members"}},
		map[string]any{"source": "discord", "external_id": "ext-bob", "user_id": "user-bob", "status": "linked", "groups": []string{"members"}},
	}
	set := doc["policy_set"].(map[string]any)
	if checks == nil {
		checks = []any{}
	}
	if toolPolicies == nil {
		toolPolicies = []any{}
	}
	set["checks"] = checks
	set["tool_policies"] = toolPolicies
	binding := map[string]any{"connector_id": "conn-a"}
	operation := func(id, capability, template string) map[string]any {
		return map[string]any{
			"id": id, "capability": capability,
			"resource":                   map[string]any{"type": "issue", "id": map[string]any{"from": "args", "pointer": "/number", "type": "integer"}, "parent": map[string]any{"type": "repository", "id": map[string]any{"from": "context", "field": "repository", "type": "string"}}},
			"provider_resource_template": template,
			"provider_input":             map[string]any{},
		}
	}
	tool := func(name, class, capability, template string) map[string]any {
		return map[string]any{
			"name": name, "source": "github", "operation_class": class,
			"route":                 map[string]any{"connector_binding": binding},
			"required_capabilities": []string{capability},
			"resource_types":        []any{map[string]any{"type": "issue", "parent_type": "repository"}},
			"plan": map[string]any{
				"args_schema":    map[string]any{"type": "object", "properties": map[string]any{"number": map[string]any{"type": "integer"}}, "required": []any{"number"}, "additionalProperties": false},
				"context_schema": map[string]any{"type": "object", "properties": map[string]any{"repository": map[string]any{"type": "string"}}, "required": []any{"repository"}, "additionalProperties": false},
				"operations":     []any{operation("op-"+name, capability, template)},
			},
		}
	}
	set["tools"] = []any{
		tool("github.get_issue", "read", "github.issues.get", "repos/{parent.id}/issues/{resource.id}"),
		tool("github.list_issues", "read", "github.issues.list", "repos/{parent.id}/issues"),
		tool("github.create_issue", "write", "github.issues.create", "repos/{parent.id}/issues"),
		map[string]any{
			"name": "opsproof_echo", "source": "discord", "operation_class": "read",
			"route": map[string]any{"harness_executor": map[string]any{"executor": "discord", "registration": "web_search"}},
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	v, err := ValidateV2(raw, v2Installation, v2Org, v2Workspace, 1, now)
	if err != nil {
		t.Fatalf("ValidateV2(op grant bundle): %v", err)
	}
	return v
}

// opGrantPermit is a tool-less capability permit: it names only a capability
// (and the connector), the shape the catalog compiles for a grant on
// capability:<operation id> (no separate tool permit).
func opGrantPermit(policyID, capability string) any {
	return map[string]any{
		"policy_id": policyID, "name": policyID, "effect": "permit", "priority": 10,
		"scope":    map[string]any{"org_id": "org-v2", "workspace_id": "ws-v2", "agent_id": "agent-a"},
		"selector": map[string]any{"source_principal": "user:user-alice", "connector_id": "conn-a", "capability": capability},
	}
}

// opGrantOps is a one-operation plan for the given capability.
func opGrantOps(capability string) []Operation {
	sum := sha256.Sum256([]byte(`{}`))
	digest := "sha256:" + hex.EncodeToString(sum[:])
	return []Operation{{
		ID: "op-1", ConnectorID: "conn-a", Capability: capability, Action: "run",
		Resource: "repos/acme/project/issues/42", InputDigest: digest, ProviderInput: json.RawMessage(`{}`),
		ResourceType: "issue", ResourceID: "42", ResourceParent: "acme/project", ResourceParentType: "repository",
		ProviderResource: "repos/acme/project/issues/42",
	}}
}

func opGrantSubject() *SessionSubject {
	return &SessionSubject{UserID: "user-alice", Source: "discord", ExternalID: "ext-alice", Status: SubjectLinked}
}

// M1: a permit on connector capability <op id> allows calls through any tool
// whose connector_binding operation is that op on that connector, without a
// separate tool permit. (Owner decision 2026-11-20, option a.)
func TestV2Plan_CapabilityPermitCoversBoundTool(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	v := opGrantBundle(t, now, []any{opGrantPermit("cap-get", "github.issues.get")}, nil, nil)
	// The plan-level allow is the loop's bare final return: it carries no
	// winner metadata, so the proof is the before/after (no_matching_policy
	// without the fix) and the scope denies below.
	d := v.EvaluateV2Plan("github.get_issue", "agent-a", opGrantSubject(), opGrantOps("github.issues.get"), now)
	if d.Outcome != "allow" {
		t.Fatalf("capability permit did not cover the bound tool: %+v", d)
	}
	// A different operation's capability stays uncovered: the permit opens
	// exactly the operation it names.
	d = v.EvaluateV2Plan("github.create_issue", "agent-a", opGrantSubject(), opGrantOps("github.issues.create"), now)
	if d.Outcome != "deny" || d.ReasonCode != "no_matching_policy" {
		t.Fatalf("capability permit leaked to another operation: %+v", d)
	}
}

// M1 scoping: a tool-less capability permit still cannot create a harness
// tool-call permit — op grants cover connector-bound tools only.
func TestV2HarnessTool_UncoveredByCapabilityPermit(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	permit := opGrantPermit("cap-get", "github.issues.get")
	v := opGrantBundle(t, now, []any{permit}, []any{permit}, nil)
	if !v.V2HarnessTool("opsproof_echo", now) {
		t.Fatal("the harness tool is not registered")
	}
	// The harness path decides tool_policies, and a tool-less capability
	// permit in that list still does not decide the call, even with
	// capability context on the request.
	subject := opGrantSubject()
	if d := v.EvaluateV2HarnessToolForTarget("opsproof_echo", "", "conn-a", "github.issues.get", "", subject, now); d.Outcome != "deny" || d.ReasonCode != "no_matching_policy" {
		t.Fatalf("harness call with capability context decided by a capability permit: %+v", d)
	}
}

// O1 (checks): a trailing .* capability permit matches by dot segment —
// github.issues.* covers get and list, and never a write.
func TestV2Plan_WildcardCapabilityPermitMatchesReadOps(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	v := opGrantBundle(t, now, []any{opGrantPermit("cap-family", "github.issues.*")}, nil, nil)
	for _, tool := range []string{"github.get_issue", "github.list_issues"} {
		capability := "github.issues.get"
		if tool == "github.list_issues" {
			capability = "github.issues.list"
		}
		d := v.EvaluateV2Plan(tool, "agent-a", opGrantSubject(), opGrantOps(capability), now)
		if d.Outcome != "allow" {
			t.Fatalf("family wildcard did not cover %s: %+v", tool, d)
		}
	}
	d := v.EvaluateV2Plan("github.create_issue", "agent-a", opGrantSubject(), opGrantOps("github.issues.create"), now)
	if d.Outcome != "deny" || d.ReasonCode != "no_matching_policy" {
		t.Fatalf("family wildcard opened a write: %+v", d)
	}
}

// M1 (grants): an access grant on the exact operation-id capability covers
// the tool bound to that operation.
func TestV2Plan_CapabilityGrantCoversBoundTool(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	grants := []any{map[string]any{
		"principal": "user:user-alice", "target": "capability:github.issues.get",
		"expire_time": now.Add(time.Hour).UTC().Format(time.RFC3339Nano),
	}}
	v := opGrantBundle(t, now, nil, nil, grants)
	// The plan-level allow carries no grant metadata (the loop's final
	// return); the proof is before/after and the denies below.
	d := v.EvaluateV2Plan("github.get_issue", "agent-a", opGrantSubject(), opGrantOps("github.issues.get"), now)
	if d.Outcome != "allow" {
		t.Fatalf("capability grant did not cover the bound tool: %+v", d)
	}
	d = v.EvaluateV2Plan("github.create_issue", "agent-a", opGrantSubject(), opGrantOps("github.issues.create"), now)
	if d.Outcome != "deny" || d.ReasonCode != ReasonNoGrantMatched {
		t.Fatalf("capability grant leaked to another operation: %+v", d)
	}
}

// O1 (grants): a trailing .* capability grant matches by dot segment —
// github.issues.* covers get and list for its principal, never a write, and
// a matched-but-ended grant denies with access_grant_expired.
func TestV2Plan_WildcardCapabilityGrantMatchesReadOps(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	live := []any{map[string]any{
		"principal": "user:user-alice", "target": "capability:github.issues.*",
		"expire_time": now.Add(time.Hour).UTC().Format(time.RFC3339Nano),
	}}
	v := opGrantBundle(t, now, nil, nil, live)
	for _, tool := range []string{"github.get_issue", "github.list_issues"} {
		capability := "github.issues.get"
		if tool == "github.list_issues" {
			capability = "github.issues.list"
		}
		d := v.EvaluateV2Plan(tool, "agent-a", opGrantSubject(), opGrantOps(capability), now)
		if d.Outcome != "allow" {
			t.Fatalf("family wildcard grant did not cover %s: %+v", tool, d)
		}
	}
	d := v.EvaluateV2Plan("github.create_issue", "agent-a", opGrantSubject(), opGrantOps("github.issues.create"), now)
	if d.Outcome != "deny" || d.ReasonCode != ReasonNoGrantMatched {
		t.Fatalf("family wildcard grant opened a write: %+v", d)
	}
	// Another principal is uncovered.
	other := &SessionSubject{UserID: "user-bob", Source: "discord", ExternalID: "ext-bob", Status: SubjectLinked}
	d = v.EvaluateV2Plan("github.get_issue", "agent-a", other, opGrantOps("github.issues.get"), now)
	if d.Outcome != "deny" || d.ReasonCode != ReasonNoGrantMatched {
		t.Fatalf("family wildcard grant covered another principal: %+v", d)
	}
	// A matched grant that has ended denies with access_grant_expired.
	expired := []any{map[string]any{
		"principal": "user:user-alice", "target": "capability:github.issues.*",
		"expire_time": now.Add(-time.Hour).UTC().Format(time.RFC3339Nano),
	}}
	v = opGrantBundle(t, now, nil, nil, expired)
	d = v.EvaluateV2Plan("github.get_issue", "agent-a", opGrantSubject(), opGrantOps("github.issues.get"), now)
	if d.Outcome != "deny" || d.ReasonCode != ReasonAccessGrantExpired {
		t.Fatalf("expired family wildcard grant = %+v, want access_grant_expired", d)
	}
}

// The capability target matcher is dot-segment: the trailing .* covers the
// remaining segments (at least one), never a different family by prefix, and
// a family wildcard never opens a write — exact targets do.
func TestCapabilityTargetMatches(t *testing.T) {
	cases := []struct {
		pattern, capability, class string
		want                       bool
	}{
		{"capability:github.issues.*", "github.issues.get", "read", true},
		{"capability:github.issues.*", "github.issues.list", "read", true},
		{"capability:github.issues.*", "github.issues.create", "write", false},
		{"capability:github.issues.*", "github.issues.get", "write", false},
		{"capability:github.issues.*", "github.issues.search.old", "read", true},
		{"capability:github.issues.*", "github.issues", "read", false},
		{"capability:github.issues.*", "github.issuesx.get", "read", false},
		{"capability:github.issue.*", "github.issues.get", "read", false},
		{"capability:github.issues.get", "github.issues.get", "write", true},
		{"capability:github.issues.get", "github.issues.list", "read", false},
	}
	for _, tc := range cases {
		if got := v2CapabilityTargetMatches(tc.pattern, tc.capability, tc.class); got != tc.want {
			t.Fatalf("v2CapabilityTargetMatches(%q, %q, %q) = %v, want %v", tc.pattern, tc.capability, tc.class, got, tc.want)
		}
	}
}

// The selector matcher treats a trailing .* capability selector by dot
// segment and requires a read-class operation; without the class dimension a
// wildcard selector matches nothing (fail closed).
func TestV2SelectorMatches_WildcardCapability(t *testing.T) {
	selector := map[string]string{"source_principal": "user:user-alice", "connector_id": "conn-a", "capability": "github.issues.*"}
	if !v2SelectorMatches(selector, map[string]string{"connector_id": "conn-a", "capability": "github.issues.get", "operation_class": "read"}) {
		t.Fatal("wildcard capability selector did not match a read operation")
	}
	if v2SelectorMatches(selector, map[string]string{"connector_id": "conn-a", "capability": "github.issues.create", "operation_class": "write"}) {
		t.Fatal("wildcard capability selector matched a write operation")
	}
	if v2SelectorMatches(selector, map[string]string{"connector_id": "conn-a", "capability": "github.issues.get"}) {
		t.Fatal("wildcard capability selector matched without the operation class dimension")
	}
	if v2SelectorMatches(selector, map[string]string{"connector_id": "conn-a", "capability": "github.issuesx.get", "operation_class": "read"}) {
		t.Fatal("wildcard capability selector matched a different family by prefix")
	}
}
