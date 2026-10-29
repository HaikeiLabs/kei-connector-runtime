package connectorruntime

import (
	"encoding/json"
	"os"
	"testing"
)

// TestValidatePolicyBundleV2SchemaAcceptsDenyOverrides proves the embedded
// closed v2 contract accepts the deny_overrides evaluation id the catalog emits
// as policy_set.evaluation.precedence (ADR-038 D-1, HAI-620), keeps accepting
// the legacy precedence, and still rejects any other precedence.
func TestValidatePolicyBundleV2SchemaAcceptsDenyOverrides(t *testing.T) {
	raw, err := os.ReadFile("docs/contracts/examples/policy-bundle-v2.payload.example.json")
	if err != nil {
		t.Fatal(err)
	}
	withPrecedence := func(precedence []string) []byte {
		t.Helper()
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		set := doc["policy_set"].(map[string]any)
		set["evaluation"].(map[string]any)["precedence"] = precedence
		out, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if err := validatePolicyBundleV2Schema(withPrecedence([]string{"deny_overrides"})); err != nil {
		t.Fatalf("v2 bundle declaring deny_overrides rejected: %v", err)
	}
	if err := validatePolicyBundleV2Schema(withPrecedence([]string{"priority_desc", "deny_before_permit", "policy_id_asc"})); err != nil {
		t.Fatalf("v2 bundle with the legacy precedence rejected: %v", err)
	}
	for name, precedence := range map[string][]string{
		"unknown id":                   {"first_match"},
		"deny_overrides plus a legacy": {"deny_overrides", "policy_id_asc"},
		"empty":                        {},
	} {
		if err := validatePolicyBundleV2Schema(withPrecedence(precedence)); err == nil {
			t.Fatalf("%s: accepted precedence %v", name, precedence)
		}
	}
}
