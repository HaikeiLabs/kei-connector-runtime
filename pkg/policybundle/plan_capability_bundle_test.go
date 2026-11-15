package policybundle

import (
	"encoding/json"
	"testing"
	"time"
)

// HAI-1050: a plan operation's capability is decided from the policy bundle
// alone, never from kei-connector-contracts' provider registry.

// A provider the contracts registry does not know is valid when its tool
// registers the capability in the bundle.
func TestV2PlanAcceptsCapabilityRegisteredOnlyInTheBundle(t *testing.T) {
	tool := v4ArrayTool("array")
	tool.Name, tool.Source, tool.RequiredCapabilities = "postgres.list_rows", "postgres", []string{"table.read"}
	var plan map[string]any
	_ = json.Unmarshal(tool.Plan, &plan)
	plan["operations"].([]any)[0].(map[string]any)["capability"] = "table.read"
	tool.Plan, _ = json.Marshal(plan)
	if err := ValidateV2Plan(tool); err != nil {
		t.Fatalf("bundle-registered capability of an unknown provider rejected: %v", err)
	}
}

// v2DescriptorToolBundle is v2ToolBundle with a connectors section whose
// conn-a descriptor declares capabilities.
func v2DescriptorToolBundle(t *testing.T, now time.Time, source string, capabilities []string) *Verified {
	t.Helper()
	base := v2ToolBundle(t, now, []any{v2Permit("p1", "pull_request.read"), v2Permit("p2", "check.read")})
	var doc map[string]any
	if err := json.Unmarshal(base.PayloadBytes, &doc); err != nil {
		t.Fatal(err)
	}
	set := doc["policy_set"].(map[string]any)
	declared := make([]any, 0, len(capabilities))
	for _, c := range capabilities {
		declared = append(declared, map[string]any{"name": c, "mutating": false})
	}
	set["connectors"] = []any{map[string]any{"id": "conn-a", "provider": source, "capabilities": declared, "credential_source": "opaque_ref", "account_model": "shared"}}
	tool := set["tools"].([]any)[0].(map[string]any)
	tool["source"] = source
	for _, check := range set["checks"].([]any) {
		check.(map[string]any)["selector"].(map[string]any)["source"] = source
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var payload Payload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	return &Verified{Payload: payload, PayloadBytes: raw, Digest: "sha256:test-v2-descriptors"}
}

func TestEvaluateV2PlanDecidesCapabilitiesFromBundleDescriptors(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	subject := &SessionSubject{UserID: "user-alice", Source: "discord", ExternalID: "ext-alice", Status: SubjectLinked}
	ops := v2TestPlanOps()
	t.Run("provider unknown to contracts with descriptor capabilities is allowed", func(t *testing.T) {
		v := v2DescriptorToolBundle(t, now, "postgres", []string{"pull_request.read", "check.read"})
		if d := v.EvaluateV2Plan("github.review_pr", "agent-a", subject, ops, now); d.Outcome != "allow" {
			t.Fatalf("decision = %+v", d)
		}
	})
	t.Run("capability absent from the connector descriptor is denied", func(t *testing.T) {
		v := v2DescriptorToolBundle(t, now, "github", []string{"pull_request.read"})
		if d := v.EvaluateV2Plan("github.review_pr", "agent-a", subject, ops, now); d.Outcome != "deny" || d.ReasonCode != "tool_not_registered" {
			t.Fatalf("decision = %+v", d)
		}
	})
	t.Run("bound connector without a descriptor is denied", func(t *testing.T) {
		v := v2DescriptorToolBundle(t, now, "github", []string{"pull_request.read", "check.read"})
		var doc map[string]any
		_ = json.Unmarshal(v.PayloadBytes, &doc)
		doc["policy_set"].(map[string]any)["connectors"].([]any)[0].(map[string]any)["id"] = "conn-other"
		raw, _ := json.Marshal(doc)
		var payload Payload
		_ = json.Unmarshal(raw, &payload)
		v = &Verified{Payload: payload, PayloadBytes: raw, Digest: "sha256:test"}
		if d := v.EvaluateV2Plan("github.review_pr", "agent-a", subject, ops, now); d.Outcome != "deny" || d.ReasonCode != "tool_not_registered" {
			t.Fatalf("decision = %+v", d)
		}
	})
	t.Run("capability absent from the tool registration is denied", func(t *testing.T) {
		v := v2DescriptorToolBundle(t, now, "postgres", []string{"pull_request.read", "check.read", "secret.write"})
		plan := append([]Operation(nil), ops...)
		plan[1].Capability = "secret.write"
		if d := v.EvaluateV2Plan("github.review_pr", "agent-a", subject, plan, now); d.Outcome != "deny" {
			t.Fatalf("decision = %+v", d)
		}
	})
}
