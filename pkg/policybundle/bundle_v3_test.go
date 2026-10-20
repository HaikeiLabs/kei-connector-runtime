package policybundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

// v3Envelope returns a valid v3 four-payload bundle document as a generic map,
// ready for json.Marshal. All payloads carry correct content digests computed
// at build time. Callers may override individual payloads to test corruption.
func v3Envelope(now time.Time) map[string]any {
	policyData := map[string]any{
		"schema":          "kei.policy-set/v2",
		"org_id":          "org-v3",
		"workspace_id":    "ws-v3",
		"match_semantics": "kei.match/v2",
		"evaluation": map[string]any{
			"precedence": []string{"priority_desc", "deny_before_permit", "policy_id_asc"},
			"checks":     "per_capability_first_match_and",
			"default":    "deny",
		},
		"tools":            []any{},
		"checks":           []any{},
		"tool_policies":    []any{},
		"harness_policies": []any{},
	}
	policyDigest := digestOf(policyData)

	return map[string]any{
		"schema":          "kei.policy-bundle/v3",
		"bundle_id":       "b3c4d5e6-f7a8-4b9c-8d0e-1f2a3b4c5d6e",
		"bundle_version":  1,
		"policy_revision": 1,
		"issuer":          Issuer,
		"audience": map[string]string{
			"installation_id": "inst-v3",
			"org_id":          "org-v3",
			"workspace_id":    "ws-v3",
		},
		"issued_at": now.UTC().Format(time.RFC3339Nano),
		"not_after": now.Add(12 * time.Hour).UTC().Format(time.RFC3339Nano),
		"refresh": map[string]int{
			"poll_interval_seconds": 60,
			"stale_after_seconds":   300,
		},
		"subject_resolution": map[string]any{
			"mode":              "online",
			"max_cache_seconds": 60,
		},
		"agent_connector_bindings": []any{},
		"payloads": map[string]any{
			"policy": map[string]any{
				"schema": "policy-bundle-v1",
				"digest": policyDigest,
				"data":   policyData,
			},
			"connectors": nil, // caller overrides this
			"harness_meta": map[string]any{
				"schema": "harness-meta-v1",
				"digest": digestOf([]any{}),
				"data":   []any{},
			},
			"model_info": map[string]any{
				"schema": "model-info-v1",
				"digest": digestOf([]any{}),
				"data":   []any{},
			},
		},
	}
}

// digestOf returns the sha256 hex digest of the JSON-marshalled v, prefixed
// with "sha256:".
func digestOf(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

func TestValidateV3ConnectorsCorruptPolicyStillLoads(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	doc := v3Envelope(now)

	// Corrupt the connectors payload: wrong digest for its content.
	payloads := doc["payloads"].(map[string]any)
	payloads["connectors"] = map[string]any{
		"schema": "connectors-v1",
		"digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"data": []any{
			map[string]any{
				"id": "some-connector",
			},
		},
	}

	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	result, err := ValidateV3(raw, "inst-v3", "org-v3", "ws-v3", 0, now)
	if err != nil {
		t.Fatalf("ValidateV3 returned error: %v", err)
	}
	if result.Policy == nil {
		t.Fatal("policy payload must load despite corrupt connectors")
	}
	if result.ConnectorsError == "" {
		t.Fatal("connectors corruption must be reported with a reason code")
	}
	if result.Connectors != nil {
		t.Fatal("connectors payload must be nil when corrupt")
	}
}
