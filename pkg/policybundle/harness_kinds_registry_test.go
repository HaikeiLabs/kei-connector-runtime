package policybundle

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func registryDoc(now time.Time, harnessKind string, kinds []any) []byte {
	doc := v2BundleDoc(now)
	doc["harness_match_semantics"] = "kei.harness-match/v1"
	doc["harnesses"] = []any{map[string]any{"agent_id": "agent-1", "kind": harnessKind}}
	if kinds != nil {
		doc["harness_kinds"] = kinds
	}
	raw, _ := json.Marshal(doc)
	return raw
}

// A harness may be of a kind only the bundle's registry names (HAI-622, CA-5);
// a bundle with no registry keeps the built-in kinds, and a malformed registry
// rejects the bundle.
func TestValidateV2HarnessKindsRegistry(t *testing.T) {
	SetV2SchemaValidator(func([]byte) error { return nil })
	t.Cleanup(func() { SetV2SchemaValidator(nil) })
	now := time.Now().UTC()
	example := map[string]any{"kind": "example", "short_name": "ex", "tool_prefix": "example.", "shell_tool": "example.shell", "gateable": true, "decides_via": "native"}

	v, err := ValidateV2(registryDoc(now, "example", []any{example}), v2Installation, v2Org, v2Workspace, 1, now)
	if err != nil {
		t.Fatalf("a kind the registry names: %v", err)
	}
	if len(v.Payload.HarnessKinds) != 1 || v.Payload.HarnessKinds[0].ShortName != "ex" {
		t.Fatalf("HarnessKinds = %+v", v.Payload.HarnessKinds)
	}
	if _, err := ValidateV2(registryDoc(now, "codex", nil), v2Installation, v2Org, v2Workspace, 1, now); err != nil {
		t.Fatalf("a built-in kind with no registry: %v", err)
	}
	if _, err := ValidateV2(registryDoc(now, "example", nil), v2Installation, v2Org, v2Workspace, 1, now); err == nil {
		t.Fatal("an unlisted kind must be rejected when the bundle has no registry")
	}
	if _, err := ValidateV2(registryDoc(now, "codex", []any{example}), v2Installation, v2Org, v2Workspace, 1, now); err == nil {
		t.Fatal("a kind missing from the bundle's registry must be rejected")
	}
	dup := []any{example, example}
	if _, err := ValidateV2(registryDoc(now, "example", dup), v2Installation, v2Org, v2Workspace, 1, now); err == nil || !strings.Contains(err.Error(), "harness_kinds") {
		t.Fatalf("a duplicate kind: err = %v, want a harness_kinds rejection", err)
	}
}
