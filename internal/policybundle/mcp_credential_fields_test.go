package policybundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

// HAI-581 item 3, contract "mcp.credential_fields exact schema" (pinned
// 2026-10-14): the v2 mcp descriptor gains an optional, closed
// credential_fields array. The catalog and runtime copies must be identical.

const pinnedCredentialFields = "testdata/mcp-credential-fields.schema.golden.json"

// TestV2SchemaCredentialFieldsMatchesThePinnedContract pins the runtime's
// copy of the schema to the contract text, both as a value and as the
// compact bytes that appear in the schema file.
func TestV2SchemaCredentialFieldsMatchesThePinnedContract(t *testing.T) {
	pinnedRaw, err := os.ReadFile(pinnedCredentialFields)
	if err != nil {
		t.Fatal(err)
	}
	var pinned struct {
		CredentialFields json.RawMessage `json:"credential_fields"`
	}
	if err := json.Unmarshal(pinnedRaw, &pinned); err != nil {
		t.Fatal(err)
	}
	schemaRaw, err := os.ReadFile("../../docs/contracts/policy-set-v2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Defs map[string]struct {
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(schemaRaw, &schema); err != nil {
		t.Fatal(err)
	}
	got, ok := schema.Defs["mcpDescriptor"].Properties["credential_fields"]
	if !ok {
		t.Fatal("the v2 schema's mcpDescriptor has no credential_fields")
	}
	var gotValue, pinnedValue any
	_ = json.Unmarshal(got, &gotValue)
	_ = json.Unmarshal(pinned.CredentialFields, &pinnedValue)
	if !reflect.DeepEqual(gotValue, pinnedValue) {
		t.Fatalf("credential_fields schema\n got %s\nwant %s", got, pinned.CredentialFields)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, pinned.CredentialFields); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(schemaRaw), `"credential_fields": `+compact.String()) {
		t.Fatalf("the schema file does not carry the pinned text byte for byte:\n%s", compact.String())
	}
}

func withCredentialFields(t *testing.T, fields any) map[string]any {
	t.Helper()
	return withMCPDescriptor(t, func(d map[string]any) {
		d["credential_source"], d["credential_ref"], d["credential_backend"] = "opaque_ref", "kei://connectors/conn-grafana/api_key", "aws-secrets-manager"
		delete(d, "account_model")
		m := d["mcp"].(map[string]any)
		m["auth_method"] = "secret_ref"
		if fields != nil {
			m["credential_fields"] = fields
		}
	})
}

func TestV2BundleDecodesMCPCredentialFields(t *testing.T) {
	v, err := validateConnectorsDoc(t, withCredentialFields(t, []any{
		map[string]any{"field": "api_key", "header": "DD-API-KEY"},
		map[string]any{"field": "app_key", "header": "DD-APPLICATION-KEY", "prefix": "Key "},
	}))
	if err != nil {
		t.Fatalf("a secret_ref mcp descriptor with credential_fields must validate: %v", err)
	}
	c, ok := v.MCPConnector("grafana_prod")
	if !ok {
		t.Fatal("descriptor not found")
	}
	want := []MCPCredentialField{{Field: "api_key", Header: "DD-API-KEY"}, {Field: "app_key", Header: "DD-APPLICATION-KEY", Prefix: "Key "}}
	if !reflect.DeepEqual(c.MCP.CredentialFields, want) {
		t.Fatalf("credential_fields = %+v, want %+v", c.MCP.CredentialFields, want)
	}
	if _, err := validateConnectorsDoc(t, withCredentialFields(t, nil)); err != nil {
		t.Fatalf("credential_fields is optional: %v", err)
	}
}

func TestV2BundleMCPCredentialFieldsSchemaRejections(t *testing.T) {
	field := func(m map[string]any) []any { return []any{m} }
	nine := make([]any, 9)
	for i := range nine {
		nine[i] = map[string]any{"field": "f" + string(rune('a'+i)), "header": "X-K" + string(rune('a'+i))}
	}
	for name, fields := range map[string]any{
		"empty array":         []any{},
		"more than 8":         nine,
		"missing header":      field(map[string]any{"field": "api_key"}),
		"missing field":       field(map[string]any{"header": "X-Key"}),
		"unknown member":      field(map[string]any{"field": "api_key", "header": "X-Key", "value": "s3cret"}),
		"bad field":           field(map[string]any{"field": "Api-Key", "header": "X-Key"}),
		"header with a space": field(map[string]any{"field": "api_key", "header": "X Key"}),
		"header with colon":   field(map[string]any{"field": "api_key", "header": "X-Key:"}),
		"header too long":     field(map[string]any{"field": "api_key", "header": "X" + strings.Repeat("a", 64)}),
		"prefix too long":     field(map[string]any{"field": "api_key", "header": "X-Key", "prefix": strings.Repeat("p", 33)}),
		"prefix with newline": field(map[string]any{"field": "api_key", "header": "X-Key", "prefix": "Bearer\n"}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validateConnectorsDoc(t, withCredentialFields(t, fields)); err == nil {
				t.Fatal("validated")
			} else if errors.Is(err, ErrBundleExpired) {
				t.Fatalf("rejected for the wrong reason: %v", err)
			}
		})
	}
}
