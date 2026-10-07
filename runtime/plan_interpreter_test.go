package runtime

import (
	"encoding/json"
	"testing"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

func TestBundlePlanInterpreterMaterializesCompositeProviderInputRefs(t *testing.T) {
	planRaw, err := json.Marshal(map[string]any{
		"args_schema":    map[string]any{"type": "object", "properties": map[string]any{"items": map[string]any{"type": "array", "maxItems": 4, "items": map[string]any{"type": "object", "properties": map[string]any{"label": map[string]any{"type": "string", "maxLength": 16}}, "required": []any{"label"}, "additionalProperties": false}}}, "required": []any{"items"}, "additionalProperties": false},
		"context_schema": map[string]any{"type": "object", "properties": map[string]any{"repository": map[string]any{"type": "string", "minLength": 1}}, "required": []any{"repository"}, "additionalProperties": false},
		"operations":     []any{map[string]any{"id": "list", "capability": "repository.read", "provider_resource_template": "repos/acme/kei", "provider_input": map[string]any{"filter": map[string]any{"ref": map[string]any{"from": "args", "pointer": "/items", "type": "array"}}, "repository": map[string]any{"ref": map[string]any{"from": "context", "field": "repository", "type": "string"}}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	tool := policybundle.V2Tool{Name: "github.list", Source: "github", RequiredCapabilities: []string{"repository.read"}, Plan: planRaw}
	tool.Route.ConnectorBinding = &struct {
		ConnectorID string `json:"connector_id"`
	}{ConnectorID: "connector-1"}
	interpreter := bundlePlanInterpreter{tool: tool}
	ops, err := interpreter.Plan([]byte(`{"items":[{"label":"one"}]}`), []byte(`{"repository":"acme/kei"}`), BindingContext{})
	if err != nil {
		t.Fatalf("interpret composite refs: %v", err)
	}
	if len(ops) != 1 || ops[0].ID != "list" || ops[0].Action != "read" || ops[0].Resource != "repos/acme/kei" {
		t.Fatalf("operation=%+v", ops)
	}
	var got map[string]any
	if err := json.Unmarshal(ops[0].ProviderInput, &got); err != nil {
		t.Fatal(err)
	}
	if got["repository"] != "acme/kei" || got["filter"] == nil {
		t.Fatalf("materialized provider input=%s", ops[0].ProviderInput)
	}
	if ops[0].InputDigest != operationInputDigest(ops[0].ProviderInput) {
		t.Fatal("provider input digest mismatch")
	}
	changed, err := interpreter.Plan([]byte(`{"items":[{"label":"two"}]}`), []byte(`{"repository":"acme/kei"}`), BindingContext{})
	if err != nil {
		t.Fatalf("replan changed input: %v", err)
	}
	if changed[0].InputDigest == ops[0].InputDigest || string(changed[0].ProviderInput) == string(ops[0].ProviderInput) {
		t.Fatal("changed provider-input template value was not rebound")
	}
}
