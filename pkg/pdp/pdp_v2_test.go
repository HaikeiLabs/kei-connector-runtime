package pdp

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

func v2SnapshotBundle(t *testing.T, now time.Time, version int64, identities []map[string]any) []byte {
	t.Helper()
	bundle := map[string]any{
		"schema": "kei.policy-bundle/v2", "bundle_id": "bundle-v2-pdp", "bundle_version": version, "policy_revision": 1, "issuer": policybundle.Issuer,
		"audience":  map[string]any{"installation_id": testInstallation, "org_id": testOrg, "workspace_id": testWorkspace},
		"issued_at": now.UTC().Format(time.RFC3339Nano), "not_after": now.Add(12 * time.Hour).UTC().Format(time.RFC3339Nano),
		"refresh":                  map[string]any{"poll_interval_seconds": 60, "stale_after_seconds": 300},
		"subject_resolution":       map[string]any{"mode": "bundle", "max_cache_seconds": 1},
		"policy_set":               map[string]any{"schema": "kei.policy-set/v2", "org_id": testOrg, "workspace_id": testWorkspace, "match_semantics": "kei.match/v2", "evaluation": map[string]any{"precedence": []string{"priority_desc", "deny_before_permit", "policy_id_asc"}, "checks": "per_capability_first_match_and", "default": "deny"}, "tools": []any{}, "checks": []any{}, "tool_policies": []any{}, "harness_match_semantics": "kei.harness-match/v1", "harness_policies": []any{}},
		"agent_connector_bindings": []any{}, "identities": identities,
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestStaleV2SnapshotHardDeniesEveryPDPEntryPoint(t *testing.T) {
	useValidator(t, schemaValidator(t))
	previous := policybundle.SetV2SchemaValidator
	_ = previous
	policybundle.SetV2SchemaValidator(func([]byte) error { return nil })
	t.Cleanup(func() { policybundle.SetV2SchemaValidator(nil) })
	now := time.Now().UTC()
	ids := []map[string]any{{"source": "discord", "external_id": "discord-old", "user_id": "u-alice", "status": "linked"}}
	bundle := v2SnapshotBundle(t, now, 42, ids)
	sessions := NewSessions()
	sessionID, err := sessions.Create(Subject{UserID: "u-alice", Source: "discord", ExternalID: "discord-old", Status: StatusLinked})
	if err != nil {
		t.Fatal(err)
	}
	if err := sessions.Start(Subject{UserID: "u-alice", Source: "discord", ExternalID: "discord-old", Status: StatusLinked}); err != nil {
		t.Fatal(err)
	}
	e, store, _ := newTestEvaluator(t, now, bundle, sessions)
	e.now = func() time.Time { return now.Add(time.Second) }
	decision, err := e.Evaluate(context.Background(), Request{Tool: "some.tool"})
	if err != nil || decision.Allow || decision.ReasonCode != "subject_snapshot_stale" {
		t.Fatalf("authorize decision=%+v err=%v", decision, err)
	}
	connector, err := e.EvaluateConnector(context.Background(), Request{Connector: &ConnectorTarget{ConnectorID: "conn", Capability: "read"}})
	if err != nil || connector.Allow || connector.ReasonCode != "subject_snapshot_stale" {
		t.Fatalf("connector decision=%+v err=%v", connector.Decision, err)
	}
	harness, err := e.EvaluateHarness(context.Background(), HarnessCall{Kind: "codex", Argv: []string{"git"}})
	if err != nil || harness.Outcome != policybundle.HarnessNotRenderable {
		t.Fatalf("harness=%+v err=%v", harness, err)
	}
	_, _, allowed, err := e.AuthorizeV2Plan(sessionID, testInstallation, "u-alice", "discord", "discord-old", testAgent, "tool", []policybundle.Operation{{ConnectorID: "conn", Capability: "read", Action: "read"}})
	if allowed || !errors.Is(err, policybundle.ErrSubjectSnapshotStale) {
		t.Fatalf("preflight allowed=%v err=%v", allowed, err)
	}
	e.ReconcileSession()
	if got, _ := sessions.Current(); got.Status != StatusRevoked {
		t.Fatalf("stale subject survived reconciliation: %+v", got)
	}
	if _, state, err := store.Check(testInstallation, testOrg, testWorkspace, now.Add(time.Second)); state != policybundle.Stale || !errors.Is(err, policybundle.ErrSubjectSnapshotStale) {
		t.Fatalf("store state=%s err=%v", state, err)
	}
}

func TestV2RefreshDoesNotPreserveRemovedRemoteIdentityByUserMembership(t *testing.T) {
	useValidator(t, schemaValidator(t))
	policybundle.SetV2SchemaValidator(func([]byte) error { return nil })
	t.Cleanup(func() { policybundle.SetV2SchemaValidator(nil) })
	now := time.Now().UTC()
	initial := v2SnapshotBundle(t, now, 42, []map[string]any{{"source": "discord", "external_id": "discord-old", "user_id": "u-alice", "status": "linked", "groups": []string{"members"}}, {"source": "slack", "external_id": "slack-still-linked", "user_id": "u-alice", "status": "linked", "groups": []string{"members"}}})
	sessions := NewSessions()
	removed, err := sessions.Create(Subject{UserID: "u-alice", Source: "discord", ExternalID: "discord-old", Status: StatusLinked})
	if err != nil {
		t.Fatal(err)
	}
	kept, err := sessions.Create(Subject{UserID: "u-alice", Source: "slack", ExternalID: "slack-still-linked", Status: StatusLinked})
	if err != nil {
		t.Fatal(err)
	}
	e, store, _ := newTestEvaluator(t, now, initial, sessions)
	next := v2SnapshotBundle(t, now.Add(time.Second), 43, []map[string]any{{"source": "slack", "external_id": "slack-still-linked", "user_id": "u-alice", "status": "linked", "groups": []string{"members"}}})
	if _, err := store.Activate(next, testInstallation, testOrg, testWorkspace, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	e.now = func() time.Time { return now.Add(time.Second) }
	revoked := e.ReconcileSessions()
	if len(revoked) != 1 || revoked[0] != removed {
		t.Fatalf("revoked session IDs=%v, want only %q", revoked, removed)
	}
	if got, ok := sessions.Get(removed); !ok || got.Status != StatusRevoked {
		t.Fatalf("removed identity session=%+v exists=%v", got, ok)
	}
	if got, ok := sessions.Get(kept); !ok || got.Status != StatusLinked {
		t.Fatalf("unrelated identity session=%+v exists=%v", got, ok)
	}
}
