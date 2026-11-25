package connectorruntime

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The embedded closed v2 contract accepts the optional connector descriptor
// fields connection and base_url (contracts v0.21.1, #137) with the same
// shape the contracts package validates, so a catalog that projects them
// never makes the whole bundle invalid, and rejects malformed values.
func TestValidatePolicyBundleV2SchemaConnectorConnectionAndBaseURL(t *testing.T) {
	withDescriptor := func(t *testing.T, mutate func(map[string]any)) []byte {
		t.Helper()
		raw, err := os.ReadFile("docs/contracts/examples/policy-bundle-v2.payload.example.json")
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		descriptor := map[string]any{
			"id": "00000000-0000-4000-8000-00000000a001", "name": "acme-github", "provider": "github", "kind": "native",
			"credential_source": "oauth", "account_model": "shared",
			"capabilities": []any{map[string]any{"name": "repository.read", "mutating": false}},
		}
		mutate(descriptor)
		doc["policy_set"].(map[string]any)["connectors"] = []any{descriptor}
		out, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if err := validatePolicyBundleV2Schema(withDescriptor(t, func(map[string]any) {})); err != nil {
		t.Fatalf("descriptor without connection/base_url rejected: %v", err)
	}
	if err := validatePolicyBundleV2Schema(withDescriptor(t, func(d map[string]any) {
		d["connection"], d["base_url"] = "pat", "https://ghe.example.com/api/v3"
	})); err != nil {
		t.Fatalf("descriptor with connection and base_url rejected: %v", err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"connection not snake_case": func(d map[string]any) { d["connection"] = "User OAuth" },
		"connection with a dot":     func(d map[string]any) { d["connection"] = "user.oauth" },
		"connection too long":       func(d map[string]any) { d["connection"] = strings.Repeat("a", 65) },
		"base_url http":             func(d map[string]any) { d["base_url"] = "http://ghe.example.com" },
		"base_url relative":         func(d map[string]any) { d["base_url"] = "/api/v3" },
		"base_url with query":       func(d map[string]any) { d["base_url"] = "https://ghe.example.com/?access_token=x" },
		"base_url with fragment":    func(d map[string]any) { d["base_url"] = "https://ghe.example.com/#x" },
		"base_url too long":         func(d map[string]any) { d["base_url"] = "https://ghe.example.com/" + strings.Repeat("a", 2048) },
		"base_url not a string":     func(d map[string]any) { d["base_url"] = 7 },
	} {
		t.Run(name, func(t *testing.T) {
			if err := validatePolicyBundleV2Schema(withDescriptor(t, mutate)); err == nil {
				t.Fatal("malformed descriptor accepted")
			}
		})
	}
}
