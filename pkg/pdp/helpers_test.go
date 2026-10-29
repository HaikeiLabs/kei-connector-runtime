package pdp

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

const (
	testInstallation = "inst-fixture-0001"
	testOrg          = "org-fixture-0001"
	testWorkspace    = "ws-fixture-0001"
	testAgent        = "agent-fixture-0001"
)

var testAudience = Audience{InstallationID: testInstallation, OrgID: testOrg, WorkspaceID: testWorkspace}

type testPolicy struct {
	ID, Src, Dst, Action string
	AgentID              string
}

// testBundle is a v2 bundle, re-dated to now, that carries policies as its
// harness policies and links no identities.
func testBundle(t *testing.T, now time.Time, version int64, policies []testPolicy) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(v2SnapshotBundle(t, now, version, []map[string]any{}), &doc); err != nil {
		t.Fatal(err)
	}
	hp := []any{}
	for i, p := range policies {
		var agent any
		if p.AgentID != "" {
			agent = p.AgentID
		}
		hp = append(hp, map[string]any{
			"policy_id": p.ID, "name": "p" + p.ID[len(p.ID)-1:], "src_pattern": p.Src, "dst_pattern": p.Dst,
			"action": p.Action, "priority": 1000 - i,
			"scope": map[string]any{"org_id": testOrg, "workspace_id": testWorkspace, "agent_id": agent},
		})
	}
	doc["policy_set"].(map[string]any)["harness_policies"] = hp
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
