package connectorruntime

import (
	"encoding/json"
	"os"
	"testing"
)

// TestValidatePolicyBundleV2SchemaAcceptsHarnessKinds proves the embedded
// closed v2 contract accepts the harness kind registry the catalog emits
// (HAI-622, CA-5), and that harnesses[].kind is no longer a fixed enum: the
// registry, validated by the contracts package, says which kinds exist.
func TestValidatePolicyBundleV2SchemaAcceptsHarnessKinds(t *testing.T) {
	raw, err := os.ReadFile("docs/contracts/examples/policy-bundle-v2.payload.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["harness_match_semantics"] = "kei.harness-match/v1"
	doc["harnesses"] = []any{map[string]any{"agent_id": "agent-fixture-0001", "kind": "pi"}}
	doc["harness_kinds"] = []any{
		map[string]any{"kind": "pi", "short_name": "pi", "tool_prefix": "pi.", "shell_tool": "pi.bash", "gateable": true, "decides_via": "pdp"},
		map[string]any{
			"kind": "claude_code", "short_name": "claude", "tool_prefix": "claude_code.", "shell_tool": "claude_code.bash", "gateable": true, "decides_via": "native",
			"native_tools": []any{map[string]any{"tool_name": "claude_code.read", "native_name": "Read"}},
		},
	}
	withKinds, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePolicyBundleV2Schema(withKinds); err != nil {
		t.Fatalf("v2 bundle with a harness kind registry rejected: %v", err)
	}
	// The registry is optional, and its entries are closed.
	delete(doc, "harness_kinds")
	doc["harnesses"] = []any{map[string]any{"agent_id": "agent-fixture-0001", "kind": "codex"}}
	without, _ := json.Marshal(doc)
	if err := validatePolicyBundleV2Schema(without); err != nil {
		t.Fatalf("v2 bundle without a registry rejected: %v", err)
	}
	doc["harness_kinds"] = []any{map[string]any{"kind": "pi", "gateable": true, "color": "blue"}}
	widened, _ := json.Marshal(doc)
	if err := validatePolicyBundleV2Schema(widened); err == nil {
		t.Fatal("accepted a registry entry carrying a field outside the contract")
	}
}

func TestValidatePolicyBundleV2SchemaRejectsAnUnknownDecidesVia(t *testing.T) {
	raw, err := os.ReadFile("docs/contracts/examples/policy-bundle-v2.payload.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["harness_kinds"] = []any{map[string]any{"kind": "pi", "gateable": true, "decides_via": "telepathy"}}
	bad, _ := json.Marshal(doc)
	if err := validatePolicyBundleV2Schema(bad); err == nil {
		t.Fatal("accepted a decides_via outside pdp|native")
	}
}
