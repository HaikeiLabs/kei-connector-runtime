package connectorruntime

import (
	"encoding/json"
	"os"
	"testing"
)

// TestValidatePolicyBundleV2SchemaAcceptsWhenHarness proves the embedded closed
// v2 contract accepts the optional when {harness} member on a harness_policies
// row (ADR-038 D-6) and still rejects every other shape, and rejects the member
// on rows of the other policy sections, which are not given the harness kind.
func TestValidatePolicyBundleV2SchemaAcceptsWhenHarness(t *testing.T) {
	raw, err := os.ReadFile("docs/contracts/examples/policy-bundle-v2.payload.example.json")
	if err != nil {
		t.Fatal(err)
	}
	withHarnessPolicy := func(extra map[string]any) []byte {
		t.Helper()
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		row := map[string]any{
			"policy_id": "policy-when", "name": "when", "src_pattern": "autogroup:member", "dst_pattern": "shell:git",
			"action": "permit", "priority": 0,
			"scope": map[string]any{"org_id": nil, "workspace_id": nil, "agent_id": nil},
		}
		for k, v := range extra {
			row[k] = v
		}
		doc["policy_set"].(map[string]any)["harness_policies"] = []any{row}
		out, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if err := validatePolicyBundleV2Schema(withHarnessPolicy(nil)); err != nil {
		t.Fatalf("row without when rejected: %v", err)
	}
	if err := validatePolicyBundleV2Schema(withHarnessPolicy(map[string]any{"when": map[string]any{"harness": "claude_code"}})); err != nil {
		t.Fatalf("row with when {harness} rejected: %v", err)
	}
	for name, when := range map[string]any{
		"empty harness":   map[string]any{"harness": ""},
		"missing harness": map[string]any{},
		"extra member":    map[string]any{"harness": "codex", "user": "x"},
		"not an object":   "codex",
		"null":            nil,
		"non-string":      map[string]any{"harness": 7},
	} {
		if err := validatePolicyBundleV2Schema(withHarnessPolicy(map[string]any{"when": when})); err == nil {
			t.Fatalf("%s: accepted when %v", name, when)
		}
	}
}
