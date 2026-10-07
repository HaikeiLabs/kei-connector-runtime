package policybundle

import (
	"encoding/json"
	"testing"
)

func v4ArrayTool(refType string) V2Tool {
	plan, _ := json.Marshal(map[string]any{
		"args_schema":    map[string]any{"type": "object", "properties": map[string]any{"items": map[string]any{"type": "array", "maxItems": 4, "items": map[string]any{"type": "object", "properties": map[string]any{"label": map[string]any{"type": "string", "maxLength": 16}}, "required": []any{"label"}, "additionalProperties": false}}}, "required": []any{"items"}, "additionalProperties": false},
		"context_schema": map[string]any{"type": "object", "properties": map[string]any{"repository": map[string]any{"type": "string", "minLength": 1}}, "required": []any{"repository"}, "additionalProperties": false},
		"operations":     []any{map[string]any{"id": "list-items", "capability": "repository.read", "provider_resource_template": "repos/acme/kei", "provider_input": map[string]any{"filter": map[string]any{"ref": map[string]any{"from": "args", "pointer": "/items", "type": refType}}, "repository": map[string]any{"ref": map[string]any{"from": "context", "field": "repository", "type": "string"}}}}},
	})
	tool := V2Tool{Name: "github.list_items", Source: "github", RequiredCapabilities: []string{"repository.read"}, Plan: plan}
	tool.Route.ConnectorBinding = &struct {
		ConnectorID string `json:"connector_id"`
	}{ConnectorID: "conn-1"}
	return tool
}

func TestV4ProviderInputAllowsTypedCompositeRefsAndRejectsMismatch(t *testing.T) {
	tool := v4ArrayTool("array")
	if err := ValidateV2Plan(tool); err != nil {
		t.Fatalf("valid typed array ref rejected: %v", err)
	}
	args, context, err := ValidatePlanData(tool, []byte(`{"items":[{"label":"one"}]}`), []byte(`{"repository":"acme/kei"}`))
	if err != nil {
		t.Fatalf("valid nested args rejected: %v", err)
	}
	if string(args) != `{"items":[{"label":"one"}]}` || string(context) != `{"repository":"acme/kei"}` {
		t.Fatalf("canonical args=%s context=%s", args, context)
	}
	if err := ValidateV2Plan(v4ArrayTool("object")); err == nil {
		t.Fatal("provider_input ref type mismatch accepted")
	}
	if _, _, err := ValidatePlanData(tool, []byte(`{"items":[]}`), []byte(`{"repository":"acme/kei","unexpected":true}`)); err == nil {
		t.Fatal("unknown context key accepted")
	}
}

func TestV4PlanRejectsUnknownRefsMissingCapabilitiesAndOperations(t *testing.T) {
	unknownContext := v4ArrayTool("array")
	var plan map[string]any
	_ = json.Unmarshal(unknownContext.Plan, &plan)
	ops := plan["operations"].([]any)
	operation := ops[0].(map[string]any)
	providerInput := operation["provider_input"].(map[string]any)
	providerInput["secret"] = map[string]any{"ref": map[string]any{"from": "context", "field": "tenant_id", "type": "string"}}
	unknownContext.Plan, _ = json.Marshal(plan)
	if err := ValidateV2Plan(unknownContext); err == nil {
		t.Fatal("undeclared context reference accepted")
	}

	for name, marker := range map[string]string{"legacy ref spelling": "$ref", "unknown wrapper key": "ref"} {
		t.Run(name, func(t *testing.T) {
			bad := v4ArrayTool("array")
			var doc map[string]any
			_ = json.Unmarshal(bad.Plan, &doc)
			operation := doc["operations"].([]any)[0].(map[string]any)
			providerInput := map[string]any{}
			if marker == "$ref" {
				providerInput["filter"] = map[string]any{"$ref": map[string]any{"from": "args", "pointer": "/items", "type": "array"}}
			} else {
				providerInput["filter"] = map[string]any{"ref": map[string]any{"from": "args", "pointer": "/items", "type": "array"}, "extra": true}
			}
			operation["provider_input"] = providerInput
			bad.Plan, _ = json.Marshal(doc)
			if err := ValidateV2Plan(bad); err == nil {
				t.Fatal("malformed provider-input ref accepted")
			}
		})
	}

	missingOperation := v4ArrayTool("array")
	_ = json.Unmarshal(missingOperation.Plan, &plan)
	plan["operations"] = []any{}
	missingOperation.Plan, _ = json.Marshal(plan)
	if err := ValidateV2Plan(missingOperation); err == nil {
		t.Fatal("missing operation accepted")
	}

	missingCapability := v4ArrayTool("array")
	missingCapability.RequiredCapabilities = []string{"repository.read", "issue.read"}
	if err := ValidateV2Plan(missingCapability); err == nil {
		t.Fatal("plan missing a required capability accepted")
	}
}

func TestV4ResourceIDReferencesRemainScalarAndProviderInputRootIsObject(t *testing.T) {
	tool := V2Tool{Name: "github.list_items", Source: "github", RequiredCapabilities: []string{"repository.read"}, ResourceTypes: []V2ResourceType{{Type: "repository"}}}
	tool.Route.ConnectorBinding = &struct {
		ConnectorID string `json:"connector_id"`
	}{ConnectorID: "conn-1"}
	base := map[string]any{"args_schema": map[string]any{"type": "object", "properties": map[string]any{"items": map[string]any{"type": "array", "maxItems": 2, "items": map[string]any{"type": "string"}}}, "additionalProperties": false}, "context_schema": map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}, "operations": []any{map[string]any{"id": "one", "capability": "repository.read", "resource": map[string]any{"type": "repository", "id": map[string]any{"from": "args", "pointer": "/items", "type": "array"}}, "provider_resource_template": "repos/{resource.id}", "provider_input": map[string]any{}}}}
	tool.Plan, _ = json.Marshal(base)
	if err := ValidateV2Plan(tool); err == nil {
		t.Fatal("composite resource id ref accepted")
	}
	base["operations"] = []any{map[string]any{"id": "one", "capability": "repository.read", "provider_resource_template": "repos/acme/kei", "provider_input": []any{"not", "object"}}}
	tool.ResourceTypes = nil
	tool.Plan, _ = json.Marshal(base)
	if err := ValidateV2Plan(tool); err == nil {
		t.Fatal("non-object provider_input root accepted")
	}
}
