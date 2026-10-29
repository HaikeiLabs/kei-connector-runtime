package runtime

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

// unsignedExampleBundle is the vendored v2 example payload re-dated to now,
// addressed to the fixture installation at bundle version 42 and policy
// revision 17. Other tests reset the global validator on cleanup, so each
// bundle installs the permissive one.
func unsignedExampleBundle(t *testing.T, now time.Time) []byte {
	t.Helper()
	policybundle.SetV2SchemaValidator(func([]byte) error { return nil })
	t.Cleanup(func() { policybundle.SetV2SchemaValidator(nil) })
	b, err := os.ReadFile("../docs/contracts/examples/policy-bundle-v2.payload.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	doc["bundle_version"] = 42
	doc["policy_revision"] = 17
	doc["audience"] = map[string]any{"installation_id": "inst-fixture-0001", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001"}
	doc["issued_at"] = now.UTC().Format(time.RFC3339)
	doc["not_after"] = now.UTC().Add(12 * time.Hour).Format(time.RFC3339)
	set := doc["policy_set"].(map[string]any)
	set["org_id"], set["workspace_id"] = "org-fixture-0001", "ws-fixture-0001"
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func mustActivateTestBundle(t *testing.T, dir string, now time.Time) (*policybundle.Verified, *policybundle.Store) {
	t.Helper()
	bundleBytes := unsignedExampleBundle(t, now)
	store, err := policybundle.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := store.Activate(bundleBytes, "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", now)
	if err != nil {
		t.Fatal(err)
	}
	return bundle, store
}
