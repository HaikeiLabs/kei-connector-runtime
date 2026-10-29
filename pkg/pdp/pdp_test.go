package pdp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

var testNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

var evaluatorPolicies = []testPolicy{
	{ID: "pol-1", Src: "*", Dst: "github:admin", Action: "deny"},
	{ID: "pol-2", Src: "user:u-alice", Dst: "github:write", Action: "permit"},
	{ID: "pol-3", Src: "group:members", Dst: "tool:search_wiki", Action: "permit"},
	{ID: "pol-4", Src: "agent:" + testAgent, Dst: "capability:issue.create", Action: "permit", AgentID: testAgent},
	{ID: "pol-5", Src: "*", Dst: "tool:search_web", Action: "permit"},
}

func TestEvaluateRuntimeStateDenies(t *testing.T) {
	useValidator(t, schemaValidator(t))
	bundle := testBundle(t, testNow, 42, evaluatorPolicies, nil)
	cases := []struct {
		name, state string
		reasonCode  ReasonCode
		setup       func(t *testing.T, e *Evaluator, store *policybundle.Store, dir string)
	}{
		{name: "cold start with no bundle", reasonCode: "policy_bundle_missing", state: "cold", setup: func(*testing.T, *Evaluator, *policybundle.Store, string) {}},
		{name: "bundle past not_after", reasonCode: "policy_bundle_expired", state: "expired", setup: func(t *testing.T, e *Evaluator, s *policybundle.Store, _ string) {
			mustActivate(t, s, bundle)
			e.now = func() time.Time { return testNow.Add(12 * time.Hour) }
		}},
		{name: "tampered persisted bundle", reasonCode: "policy_bundle_invalid", state: "invalid", setup: func(t *testing.T, _ *Evaluator, s *policybundle.Store, dir string) {
			mustActivate(t, s, bundle)
			path := filepath.Join(dir, "policy", "bundle.json")
			b, _ := os.ReadFile(path)
			b[len(b)-1] = ' '
			if err := os.WriteFile(path, append(b, '}'), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "installation revoked", reasonCode: "installation_revoked", state: "revoked", setup: func(t *testing.T, _ *Evaluator, s *policybundle.Store, _ string) {
			mustActivate(t, s, bundle)
			if err := s.Revoke(testNow); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sessions := NewSessions()
			sessionID, err := sessions.Create(Subject{UserID: "u-fixture", Status: StatusLinked})
			if err != nil {
				t.Fatal(err)
			}
			e, store, dir := newTestEvaluator(t, testNow, nil, sessions)
			tc.setup(t, e, store, dir)
			d, err := e.Evaluate(context.Background(), Request{Session: sessionID, Tool: "search_web"})
			if err != nil {
				t.Fatal(err)
			}
			if d.Allow || d.ReasonCode != tc.reasonCode || d.DenySource != "runtime_state" || d.BundleState != tc.state || d.PolicyID != "" {
				t.Fatalf("decision = %+v, want deny %s in state %s", d, tc.reasonCode, tc.state)
			}
		})
	}
}

func TestEvaluateRespectsCanceledContext(t *testing.T) {
	useValidator(t, schemaValidator(t))
	e, _, _ := newTestEvaluator(t, testNow, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Evaluate(ctx, Request{Tool: "search_web"}); err == nil {
		t.Fatal("Evaluate ignored a canceled context")
	}
}

// useV2Fixtures installs the permissive v2 schema validator the v2 fixtures use.
func useV2Fixtures(t *testing.T) {
	t.Helper()
	policybundle.SetV2SchemaValidator(func([]byte) error { return nil })
	t.Cleanup(func() { policybundle.SetV2SchemaValidator(nil) })
}

// v2Identities links alice and bob in a v2 bundle's identity snapshot.
func v2Identities() []map[string]any {
	return []map[string]any{
		{"source": "discord", "external_id": "ext-alice", "user_id": "u-alice", "status": "linked"},
		{"source": "discord", "external_id": "ext-bob", "user_id": "u-bob", "status": "linked"},
	}
}

func TestSessionLifecycle(t *testing.T) {
	useV2Fixtures(t)
	sessions := NewSessions()
	e, _, _ := newTestEvaluator(t, testNow, v2SnapshotBundle(t, testNow, 42, v2Identities()), sessions)
	if _, err := sessions.Create(Subject{Status: StatusLinked}); err == nil {
		t.Fatal("a linked session started without a user id")
	}
	sessionID, err := sessions.Create(Subject{UserID: "u-alice", Source: "discord", ExternalID: "ext-alice", Status: StatusLinked})
	if err != nil {
		t.Fatal(err)
	}
	status := func() Status {
		t.Helper()
		sub, ok := sessions.Get(sessionID)
		if !ok {
			t.Fatal("session is gone")
		}
		return sub.Status
	}
	e.ReconcileSession()
	e.memberships = func(*policybundle.Verified, time.Time) policybundle.Memberships {
		return fakeMemberships{"u-alice": {granted: true}}
	}
	e.ReconcileSession() // the bundle still grants alice: nothing to revoke
	if got := status(); got != StatusLinked {
		t.Fatalf("status = %s after a reconcile that still grants alice, want linked", got)
	}
	e.memberships = func(*policybundle.Verified, time.Time) policybundle.Memberships {
		return fakeMemberships{"u-alice": {granted: false}}
	}
	e.ReconcileSession()
	e.memberships = policybundle.BundleMembershipsAt
	if got := status(); got != StatusRevoked {
		t.Fatalf("status = %s after the bundle stopped granting alice, want revoked", got)
	}
	sessions.EndID(sessionID)
	if d, _ := e.Evaluate(context.Background(), Request{Session: sessionID, Tool: "github.create_issue"}); d.ReasonCode != ReasonSessionNotFound {
		t.Fatalf("reason_code = %q, want %q for an ended session", d.ReasonCode, ReasonSessionNotFound)
	}
	sessionID, err = sessions.Create(Subject{UserID: "u-alice", Source: "discord", ExternalID: "ext-alice", Status: StatusLinked})
	if err != nil {
		t.Fatal(err)
	}
	e.RevokeSession()
	if got := status(); got != StatusRevoked {
		t.Fatalf("status = %s after installation revocation, want revoked", got)
	}
}
func TestReconcileBundleSessionRevokesWhenIdentitySnapshotDropsSubject(t *testing.T) {
	useValidator(t, schemaValidator(t))
	bundle := testBundle(t, testNow, 42, evaluatorPolicies, nil)
	var doc map[string]any
	if err := json.Unmarshal(bundle, &doc); err != nil {
		t.Fatal(err)
	}
	doc["subject_resolution"] = map[string]any{"mode": "bundle", "max_cache_seconds": 60}
	doc["identities"] = []any{map[string]any{
		"source": "discord", "external_id": "discord-user", "user_id": "u-alice", "status": "linked",
	}}
	bundle, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	sessions := NewSessions()
	sessionID, err := sessions.Create(Subject{UserID: "u-alice", Source: "discord", ExternalID: "discord-user", Status: StatusLinked})
	if err != nil {
		t.Fatal(err)
	}
	e, store, _ := newTestEvaluator(t, testNow, bundle, sessions)
	e.ReconcileSession()
	if got, ok := sessions.Get(sessionID); !ok || got.Status != StatusLinked {
		t.Fatalf("named session revoked linked identity: %+v exists=%t", got, ok)
	}

	doc["bundle_version"] = 43
	doc["issued_at"] = testNow.Add(time.Second).Format(time.RFC3339)
	doc["not_after"] = testNow.Add(12 * time.Hour).Format(time.RFC3339)
	doc["identities"] = []any{}
	bundle, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(bundle, testInstallation, testOrg, testWorkspace, testNow.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	e.now = func() time.Time { return testNow.Add(time.Second) }
	e.ReconcileSession()
	if got, ok := sessions.Get(sessionID); !ok || got.Status != StatusRevoked {
		t.Fatalf("identity removed from refreshed snapshot left session %s", got.Status)
	}
}

func mustActivate(t *testing.T, s *policybundle.Store, bundle []byte) {
	t.Helper()
	if _, err := s.Activate(bundle, testInstallation, testOrg, testWorkspace, testNow); err != nil {
		t.Fatal(err)
	}
}
