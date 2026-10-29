package policybundle

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

// realSchemaValidator compiles and returns a validator against the vendored
// canonical v2 schemas — the same path the real runtime init() in
// policy_schema.go uses. This is the actual gate that rejects production
// bundles (the Go struct's DisallowUnknownFields is a secondary safeguard).
func realSchemaValidator(t *testing.T) func([]byte) error {
	t.Helper()
	load := func(path string) any {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource("https://schemas.haikeilabs.com/kei/policy-set-v2.schema.json", load("../../docs/contracts/policy-set-v2.schema.json")); err != nil {
		t.Fatal(err)
	}
	if err := c.AddResource("https://schemas.haikeilabs.com/kei/policy-bundle-v2.schema.json", load("../../docs/contracts/policy-bundle-v2.schema.json")); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("https://schemas.haikeilabs.com/kei/policy-bundle-v2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return func(raw []byte) error {
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			return err
		}
		return s.Validate(doc)
	}
}

// useValidator installs a schema validator for the lifetime of a test.
// The policybundle package init in store_test.go sets the default validator
// to a no-op, so tests that need end-to-end validation must install the real
// one.
func useValidator(t *testing.T, v func([]byte) error) {
	t.Helper()
	prev := schemaValidatorV2
	SetV2SchemaValidator(v)
	t.Cleanup(func() { SetV2SchemaValidator(prev) })
}

// validPolicySet returns a minimal policy_set that satisfies the vendored
// policy-set-v2.schema.json.
func validPolicySet() map[string]any {
	return map[string]any{
		"schema":                  "kei.policy-set/v2",
		"org_id":                  "org-001",
		"workspace_id":            "ws-001",
		"match_semantics":         "kei.match/v2",
		"evaluation":              map[string]any{"precedence": []any{"priority_desc", "deny_before_permit", "policy_id_asc"}, "checks": "per_capability_first_match_and", "default": "deny"},
		"tools":                   []any{},
		"checks":                  []any{},
		"tool_policies":           []any{},
		"harness_policies":        []any{},
		"harness_match_semantics": "kei.harness-match/v1",
	}
}

// jsonBundle is a convenience for building test bundle JSON with a valid
// policy_set without repeating boilerplate. Fields in extra override the base.
func jsonBundle(extra map[string]any) []byte {
	base := map[string]any{
		"schema":                   "kei.policy-bundle/v2",
		"bundle_id":                "bundle-h001",
		"bundle_version":           42,
		"policy_revision":          1,
		"issuer":                   "kei-policy-catalog",
		"audience":                 map[string]any{"installation_id": "inst-001", "org_id": "org-001", "workspace_id": "ws-001"},
		"issued_at":                "2026-10-01T11:00:00Z",
		"not_after":                "2026-10-01T23:00:00Z",
		"refresh":                  map[string]any{"poll_interval_seconds": 300, "stale_after_seconds": 600},
		"subject_resolution":       map[string]any{"mode": "bundle", "max_cache_seconds": 30},
		"policy_set":               validPolicySet(),
		"agent_connector_bindings": []any{},
		"identities":               []any{},
	}
	for k, v := range extra {
		base[k] = v
	}
	b, _ := json.Marshal(base)
	return b
}

func TestBundleHarnessesAcceptsValidHarnesses(t *testing.T) {
	useValidator(t, realSchemaValidator(t))

	raw := jsonBundle(map[string]any{
		"harnesses": []any{
			map[string]any{"agent_id": "agent-claude-001", "kind": "claude_code"},
			map[string]any{"agent_id": "agent-codex-002", "kind": "codex"},
			map[string]any{"agent_id": "agent-opencode-003", "kind": "opencode"},
			map[string]any{"agent_id": "agent-custom-004", "kind": "custom"},
		},
		"harness_match_semantics": "kei.harness-match/v1",
	})
	v, err := Validate(raw, "inst-001", "org-001", "ws-001", 41, time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(v.Payload.Harnesses) != 4 {
		t.Fatalf("expected 4 harnesses, got %d", len(v.Payload.Harnesses))
	}
	if v.Payload.Harnesses[0].AgentID != "agent-claude-001" || v.Payload.Harnesses[0].Kind != "claude_code" {
		t.Fatalf("harness[0] = %+v", v.Payload.Harnesses[0])
	}
	if v.Payload.HarnessMatchSemantics != "kei.harness-match/v1" {
		t.Fatalf("harness_match_semantics = %q", v.Payload.HarnessMatchSemantics)
	}
}

func TestBundleHarnessesAcceptsHarnessesWithIdentities(t *testing.T) {
	useValidator(t, realSchemaValidator(t))

	raw := jsonBundle(map[string]any{
		"subject_resolution": map[string]any{"mode": "bundle", "max_cache_seconds": 0},
		"identities": []any{
			map[string]any{"source": "discord", "external_id": "ext-001", "user_id": "usr-001", "status": "linked", "groups": []any{}, "org_roles": []any{}},
		},
		"harnesses": []any{
			map[string]any{"agent_id": "agent-custom-004", "kind": "custom"},
		},
		"harness_match_semantics": "kei.harness-match/v1",
	})
	v, err := Validate(raw, "inst-001", "org-001", "ws-001", 0, time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Validate with identities + harnesses: %v", err)
	}
	if len(v.Payload.Identities) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(v.Payload.Identities))
	}
	if len(v.Payload.Harnesses) != 1 {
		t.Fatalf("expected 1 harness, got %d", len(v.Payload.Harnesses))
	}
}

func TestBundleHarnessesRejectsUnknownTopLevelField(t *testing.T) {
	useValidator(t, realSchemaValidator(t))

	raw := jsonBundle(map[string]any{
		"unknown_field": "should be rejected",
	})
	_, err := Validate(raw, "inst-001", "org-001", "ws-001", 41, time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatal("expected error for unknown field, got nil")
	}
	if !strings.Contains(err.Error(), "closed v2 schema rejected unknown field") {
		t.Fatalf("expected closed schema error, got %v", err)
	}
}

func TestBundleHarnessesRejectsInvalidKind(t *testing.T) {
	useValidator(t, realSchemaValidator(t))

	raw := jsonBundle(map[string]any{
		"harnesses":               []any{map[string]any{"agent_id": "agent-001", "kind": "unknown"}},
		"harness_match_semantics": "kei.harness-match/v1",
	})
	_, err := Validate(raw, "inst-001", "org-001", "ws-001", 41, time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatal("expected error for invalid kind, got nil")
	}
	// The kind is not a fixed enum in the v2 schema: Go-level validateHarnesses
	// checks it against the bundle's registry (or the built-in kinds).
	if !strings.Contains(err.Error(), "is not a valid harness kind") {
		t.Fatalf("expected an invalid harness kind error, got %v", err)
	}
}

func TestBundleHarnessesRejectsKindAsAgentID(t *testing.T) {
	useValidator(t, realSchemaValidator(t))

	raw := jsonBundle(map[string]any{
		"harnesses":               []any{map[string]any{"agent_id": "claude_code", "kind": "claude_code"}},
		"harness_match_semantics": "kei.harness-match/v1",
	})
	_, err := Validate(raw, "inst-001", "org-001", "ws-001", 41, time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatal("expected error for agent_id equal to kind value, got nil")
	}
	// Go-level validateHarnesses refuses an agent_id that equals a kind value.
	if !strings.Contains(err.Error(), "must not equal a harness kind value") {
		t.Fatalf("expected an agent_id/kind collision error, got %v", err)
	}
}

func TestBundleHarnessesRejectsInvalidAgentID(t *testing.T) {
	useValidator(t, realSchemaValidator(t))

	raw := jsonBundle(map[string]any{
		"harnesses":               []any{map[string]any{"agent_id": "", "kind": "claude_code"}},
		"harness_match_semantics": "kei.harness-match/v1",
	})
	_, err := Validate(raw, "inst-001", "org-001", "ws-001", 41, time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatal("expected error for empty agent_id, got nil")
	}
	// The JSON schema pattern rejects empty agent_id before Go-level
	// validateHarnesses runs.
	if !strings.Contains(err.Error(), "does not match pattern") {
		t.Fatalf("expected pattern validation error, got %v", err)
	}
}

func TestBundleHarnessesAcceptsBundleWithoutHarnesses(t *testing.T) {
	useValidator(t, realSchemaValidator(t))

	raw := jsonBundle(nil)
	v, err := Validate(raw, "inst-001", "org-001", "ws-001", 41, time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(v.Payload.Harnesses) != 0 {
		t.Fatalf("expected empty harnesses, got %d", len(v.Payload.Harnesses))
	}
	if v.Payload.HarnessMatchSemantics != "" {
		t.Fatalf("expected empty harness_match_semantics, got %q", v.Payload.HarnessMatchSemantics)
	}
}

func TestBundleHarnessesRejectsHarnessesWithoutSemantics(t *testing.T) {
	useValidator(t, realSchemaValidator(t))

	raw := jsonBundle(map[string]any{
		"harnesses": []any{map[string]any{"agent_id": "agent-001", "kind": "claude_code"}},
	})
	_, err := Validate(raw, "inst-001", "org-001", "ws-001", 41, time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatal("expected error for harnesses without harness_match_semantics, got nil")
	}
	// The JSON schema enforces conditional required: if harnesses exists,
	// harness_match_semantics must be present.
	if !strings.Contains(err.Error(), "required, if 'harnesses' exists") {
		t.Fatalf("expected conditional required error, got %v", err)
	}
}

// contractPropertyNames returns the "properties" key set from the vendored
// policy-bundle-v2.schema.json. This is the canonical list of every field the
// contract permits at the bundle payload top level.
func contractPropertyNames(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile("../../docs/contracts/policy-bundle-v2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties map[string]any `json:"properties"`
	}
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatal(err)
	}
	m := make(map[string]bool, len(schema.Properties))
	for k := range schema.Properties {
		m[k] = true
	}
	return m
}

// payloadJSONFieldNames returns the set of JSON field names that the Payload
// struct will accept (from json tags). Fields with `json:"...,omitempty"` are
// included; the empty name (json:"-") is excluded.
func payloadJSONFieldNames() map[string]bool {
	t := reflect.TypeOf(Payload{})
	m := make(map[string]bool)
	for _, f := range reflect.VisibleFields(t) {
		if !f.IsExported() {
			continue
		}
		// VisibleFields lists the anonymous embedded field itself (Index=[0])
		// and every promoted field (Index=[0,…]). Skip the direct anonymous
		// field — its json fields are promoted and listed separately.
		if len(f.Index) == 1 && f.Anonymous {
			continue
		}
		tag := f.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			continue
		}
		m[name] = true
	}
	return m
}

func TestBundleHarnessesContractParityKnownProperties(t *testing.T) {
	// Every property in the vendored schema's "properties" map must have a
	// corresponding Go struct field.
	schemaProps := contractPropertyNames(t)
	goFields := payloadJSONFieldNames()

	for prop := range schemaProps {
		if !goFields[prop] {
			t.Errorf("schema property %q has no corresponding Go struct field", prop)
		}
	}
	for field := range goFields {
		if !schemaProps[field] {
			t.Errorf("Go struct has field %q not in schema properties", field)
		}
	}
}

func TestBundleHarnessesContractParityRoundTrip(t *testing.T) {
	useValidator(t, realSchemaValidator(t))

	// Round-trip: marshal a payload with all contract properties (non-zero
	// omitempty values), verify the schema validator and strictJSON accept it.
	raw := jsonBundle(map[string]any{
		"identities":              []any{},
		"harnesses":               []any{},
		"harness_match_semantics": "kei.harness-match/v1",
	})
	var p Payload
	if err := strictJSON(raw, &p); err != nil {
		t.Fatalf("strictJSON with all contract properties: %v", err)
	}
	_, err := Validate(raw, "inst-001", "org-001", "ws-001", 0, time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Validate with all contract properties: %v", err)
	}
}

func TestBundleHarnessesFixtureExampleDecodes(t *testing.T) {
	// The canonical example bundle (no harnesses) must still decode with the
	// updated vendored schemas.
	useValidator(t, realSchemaValidator(t))

	raw := fixtureBundle(t)
	v, err := Validate(raw, "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", 0, fixtureNow())
	if err != nil {
		t.Fatalf("Validate example bundle: %v", err)
	}
	if len(v.Payload.Harnesses) != 0 {
		t.Fatalf("example bundle should have empty harnesses, got %d", len(v.Payload.Harnesses))
	}
}
