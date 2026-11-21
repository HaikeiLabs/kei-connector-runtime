package policybundle

import (
	"encoding/json"
	"testing"
	"time"
)

// TestValidateV2_AcceptsBindingResourceTemplate proves the closed v2 contract
// accepts the resource_template and version fields the catalog carries on a
// route's connector_binding (resource-template authorization): a bundle that
// carries them is usable, not invalid. A binding that carries any other field
// outside the contract is still rejected. The tool is built exactly like the
// connector-bound tool in v2ToolBundle (evaluate_v2_test.go).
func TestValidateV2_AcceptsBindingResourceTemplate(t *testing.T) {
	previous := schemaValidatorV2
	SetV2SchemaValidator(v2SchemaValidator(t))
	t.Cleanup(func() { SetV2SchemaValidator(previous) })
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	marshal := func(binding map[string]any) []byte {
		t.Helper()
		doc := v2BundleDoc(now)
		doc["agent_connector_bindings"] = []any{map[string]any{"agent_id": "agent-a", "connector_id": "conn-a", "capabilities": []string{"pull_request.read", "check.read"}}}
		set := doc["policy_set"].(map[string]any)
		set["tools"] = []any{map[string]any{
			"name": "github.review_pr", "source": "github", "operation_class": "read",
			"route":                 map[string]any{"connector_binding": binding},
			"required_capabilities": []string{"pull_request.read", "check.read"},
			"resource_types":        []any{map[string]any{"type": "pull_request", "parent_type": "repository"}},
			"plan": map[string]any{
				"args_schema":    map[string]any{"type": "object", "properties": map[string]any{"number": map[string]any{"type": "integer"}}, "required": []any{"number"}, "additionalProperties": false},
				"context_schema": map[string]any{"type": "object", "properties": map[string]any{"repository": map[string]any{"type": "string"}}, "required": []any{"repository"}, "additionalProperties": false},
				"operations": []any{
					map[string]any{"id": "read-pull-request", "capability": "pull_request.read", "resource": map[string]any{"type": "pull_request", "id": map[string]any{"from": "args", "pointer": "/number", "type": "integer"}, "parent": map[string]any{"type": "repository", "id": map[string]any{"from": "context", "field": "repository", "type": "string"}}}, "provider_resource_template": "repos/{parent.id}/pulls/{resource.id}", "provider_input": map[string]any{}},
					map[string]any{"id": "read-checks", "capability": "check.read", "resource": map[string]any{"type": "pull_request", "id": map[string]any{"from": "args", "pointer": "/number", "type": "integer"}, "parent": map[string]any{"type": "repository", "id": map[string]any{"from": "context", "field": "repository", "type": "string"}}}, "provider_resource_template": "repos/{parent.id}/pulls/{resource.id}", "provider_input": map[string]any{}},
				},
			},
		}}
		set["checks"] = []any{}
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	withTemplate := map[string]any{
		"connector_id":      "conn-a",
		"resource_template": "repos/{owner}/{repository}",
		"version":           "v0.19.0",
	}
	if _, err := ValidateV2(marshal(withTemplate), v2Installation, v2Org, v2Workspace, 1, now); err != nil {
		t.Fatalf("ValidateV2 rejected a binding with resource_template and version: %v", err)
	}

	unknown := map[string]any{
		"connector_id":      "conn-a",
		"resource_template": "repos/{owner}/{repository}",
		"version":           "v0.19.0",
		"scope":             "workspace",
	}
	if _, err := ValidateV2(marshal(unknown), v2Installation, v2Org, v2Workspace, 1, now); err == nil {
		t.Fatal("accepted a binding carrying a field outside the contract")
	}
}
