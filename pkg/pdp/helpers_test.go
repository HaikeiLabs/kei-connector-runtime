package pdp

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	testInstallation = "inst-fixture-0001"
	testOrg          = "org-fixture-0001"
	testWorkspace    = "ws-fixture-0001"
	testAgent        = "agent-fixture-0001"
)

var testAudience = Audience{InstallationID: testInstallation, OrgID: testOrg, WorkspaceID: testWorkspace}

// schemaValidator validates against the vendored canonical schemas, the same
// way the runtime root package does.
func schemaValidator(t *testing.T) func([]byte) error {
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
	if err := c.AddResource("https://schemas.haikeilabs.com/kei/policy-set-v1.schema.json", load("../../docs/contracts/policy-set-v1.schema.json")); err != nil {
		t.Fatal(err)
	}
	if err := c.AddResource("https://schemas.haikeilabs.com/kei/policy-bundle-v1.schema.json", load("../../docs/contracts/policy-bundle-v1.schema.json")); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("https://schemas.haikeilabs.com/kei/policy-bundle-v1.schema.json")
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

func useValidator(t *testing.T, v func([]byte) error) {
	t.Helper()
	policybundle.SetSchemaValidator(v)
	t.Cleanup(func() { policybundle.SetSchemaValidator(nil) })
}

type testPolicy struct {
	ID, Src, Dst, Action string
	AgentID              string
}

// testBundle is the canonical example payload, re-dated to now, with its
// policies (and optionally its bindings) replaced.
func testBundle(t *testing.T, now time.Time, version int64, policies []testPolicy, bindings []map[string]any) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../docs/contracts/examples/policy-bundle-v1.payload.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	doc["bundle_version"] = version
	doc["issued_at"] = now.UTC().Format(time.RFC3339)
	doc["not_after"] = now.UTC().Add(12 * time.Hour).Format(time.RFC3339)
	set := doc["policy_set"].(map[string]any)
	var ps []any
	for i, p := range policies {
		var agent any
		if p.AgentID != "" {
			agent = p.AgentID
		}
		ps = append(ps, map[string]any{
			"id": p.ID, "name": "p" + p.ID[len(p.ID)-1:], "src_pattern": p.Src, "dst_pattern": p.Dst,
			"action": p.Action, "priority": 1000 - i, "enabled": true, "approval_required": false,
			"scope": map[string]any{"org_id": testOrg, "workspace_id": testWorkspace, "agent_id": agent},
		})
	}
	set["policies"] = ps
	if bindings != nil {
		doc["agent_connector_bindings"] = bindings
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// newTestEvaluator activates bundle (when non-nil) in a fresh state directory.
func newTestEvaluator(t *testing.T, now time.Time, bundle []byte, sessions *Sessions) (*Evaluator, *policybundle.Store, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := policybundle.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if bundle != nil {
		if _, err := store.Activate(bundle, testInstallation, testOrg, testWorkspace, now); err != nil {
			t.Fatalf("activate test bundle: %v", err)
		}
	}
	e, err := New(dir, testAudience, sessions)
	if err != nil {
		t.Fatal(err)
	}
	e.now = func() time.Time { return now }
	return e, store, dir
}

type fakeMemberships map[string]struct {
	groups  []string
	granted bool
}

func (f fakeMemberships) Lookup(userID string) ([]string, []string, bool, bool) {
	m, ok := f[userID]
	if !ok {
		return nil, nil, false, true
	}
	return m.groups, nil, m.granted, true
}
