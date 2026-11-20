package policybundle

import (
	"encoding/json"
	"testing"
	"time"
)

// A catalog-shaped v2 bundle whose connector tool carries resource_template
// and version on its binding. Built through the real ValidateV2 with the
// runtime v2 schema validator, exactly like the catalog emits it
// (opsproof Run 2 G4: the contracts strict decode cannot parse this shape,
// so the lookups must run on the runtime's own types).
func templatedToolsBundle(t *testing.T, now time.Time) *Verified {
	t.Helper()
	previous := schemaValidatorV2
	SetV2SchemaValidator(v2SchemaValidator(t))
	t.Cleanup(func() { SetV2SchemaValidator(previous) })

	doc := v2BundleDoc(now)
	doc["agent_connector_bindings"] = []any{map[string]any{"agent_id": "agent-a", "connector_id": "conn-a", "capabilities": []string{"issue.read"}}}
	set := doc["policy_set"].(map[string]any)
	set["tools"] = []any{
		map[string]any{
			"name": "github.get_issue", "source": "github", "operation_class": "read",
			"route":                 map[string]any{"connector_binding": map[string]any{"connector_id": "conn-a", "resource_template": "repos/{owner}/{repository}", "version": "v0.19.0"}},
			"required_capabilities": []string{"issue.read"},
			"resource_types":        []any{map[string]any{"type": "issue", "parent_type": "repository"}},
			"plan": map[string]any{
				"args_schema":    map[string]any{"type": "object", "properties": map[string]any{"number": map[string]any{"type": "integer"}}, "required": []any{"number"}, "additionalProperties": false},
				"context_schema": map[string]any{"type": "object", "properties": map[string]any{"repository": map[string]any{"type": "string"}}, "required": []any{"repository"}, "additionalProperties": false},
				"operations": []any{
					map[string]any{"id": "get-issue", "capability": "issue.read", "resource": map[string]any{"type": "issue", "id": map[string]any{"from": "args", "pointer": "/number", "type": "integer"}, "parent": map[string]any{"type": "repository", "id": map[string]any{"from": "context", "field": "repository", "type": "string"}}}, "provider_resource_template": "repos/{parent.id}/issues/{resource.id}", "provider_input": map[string]any{}},
				},
			},
		},
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
		t.Fatalf("ValidateV2(templated bundle): %v", err)
	}
	return v
}

func TestV2ConnectorTool_FindsToolWithResourceTemplate(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	v := templatedToolsBundle(t, now)
	tool, ok := v.V2ConnectorTool("github.get_issue", now)
	if !ok {
		t.Fatal("V2ConnectorTool did not find a connector tool whose binding carries resource_template and version")
	}
	if tool.Name != "github.get_issue" || tool.Route.ConnectorBinding == nil || tool.Route.ConnectorBinding.ConnectorID != "conn-a" {
		t.Fatalf("tool = %+v, want github.get_issue bound to conn-a", tool)
	}
}

func TestV2HarnessTool_UnaffectedByTemplatedConnectorTool(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	v := templatedToolsBundle(t, now)
	if !v.V2HarnessTool("opsproof_echo", now) {
		t.Fatal("V2HarnessTool did not find the harness tool in a bundle whose connector tool carries resource_template")
	}
	if v.V2HarnessTool("github.get_issue", now) {
		t.Fatal("V2HarnessTool reported a connector tool as a harness tool")
	}
	if _, ok := v.V2ConnectorTool("opsproof_echo", now); ok {
		t.Fatal("V2ConnectorTool reported a harness tool as a connector tool")
	}
}
