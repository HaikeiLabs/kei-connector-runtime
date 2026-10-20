package connectorruntime

import (
	"encoding/json"
	"os"
	"testing"
)

// TestValidatePolicyBundleV2SchemaAcceptsAccessGrants proves the embedded
// closed v2 contract accepts the access_grants projection the catalog emits
// (ADR-038, HAI-615). The contract is closed, so without the field every
// bundle that carries a grant is rejected as unsupported and the
// installation denies every call.
func TestValidatePolicyBundleV2SchemaAcceptsAccessGrants(t *testing.T) {
	raw, err := os.ReadFile("docs/contracts/examples/policy-bundle-v2.payload.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["access_grants"] = []any{map[string]any{
		"principal": "user:user-alice", "target": "tool:web_search",
		"expire_time": "2026-10-05T13:00:00Z",
	}}
	withGrants, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePolicyBundleV2Schema(withGrants); err != nil {
		t.Fatalf("v2 bundle with access grants rejected: %v", err)
	}
	// The projection is optional: a bundle issued before it existed still
	// validates.
	if err := validatePolicyBundleV2Schema(raw); err != nil {
		t.Fatalf("v2 bundle without access grants rejected: %v", err)
	}
	// The grant entry is closed too: a grant carries the principal, the
	// target and the expiry, and nothing else.
	doc["access_grants"] = []any{map[string]any{
		"principal": "user:user-alice", "target": "tool:web_search",
		"expire_time": "2026-10-05T13:00:00Z", "reason": "why the grant exists",
	}}
	widened, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePolicyBundleV2Schema(widened); err == nil {
		t.Fatal("accepted a grant carrying a field outside the contract")
	}
}
