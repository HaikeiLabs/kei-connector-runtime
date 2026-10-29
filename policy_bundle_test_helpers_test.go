package connectorruntime

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

// unsignedExampleBundle is the vendored v2 example payload re-dated to now and
// addressed to the fixture installation. The root package installs the real v2
// schema validator, so it is validated against the closed schema.
func unsignedExampleBundle(t *testing.T, now time.Time) []byte {
	t.Helper()
	b, err := os.ReadFile("docs/contracts/examples/policy-bundle-v2.payload.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
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
	store, err := policybundle.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := store.Activate(unsignedExampleBundle(t, now), "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", now)
	if err != nil {
		t.Fatal(err)
	}
	return bundle, store
}
