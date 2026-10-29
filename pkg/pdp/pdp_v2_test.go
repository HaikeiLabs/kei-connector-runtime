package pdp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
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

func TestV2SnapshotFreshAfterMaxCacheWindow(t *testing.T) {
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
	e, store, _ := newTestEvaluator(t, now, bundle, sessions)
	e.now = func() time.Time { return now.Add(time.Second) }
	// HAI-452: the subject snapshot is no longer stale after the old
	// max_cache_seconds window. Every PDP entry point proceeds past the
	// staleness gate and makes its normal decision.

	decision, err := e.Evaluate(context.Background(), Request{Session: sessionID, Tool: "some.tool"})
	if err != nil || decision.Allow || decision.ReasonCode != "preflight_required" {
		t.Fatalf("authorize decision=%+v err=%v", decision, err)
	}
	connector, err := e.EvaluateConnector(context.Background(), Request{Session: sessionID, Connector: &ConnectorTarget{ConnectorID: "conn", Capability: "read"}})
	if err != nil || connector.Allow || connector.ReasonCode != "preflight_required" {
		t.Fatalf("connector decision=%+v err=%v", connector.Decision, err)
	}
	harness, err := e.EvaluateHarness(context.Background(), HarnessCall{Kind: "codex", Argv: []string{"git"}})
	if err != nil || harness.Outcome != policybundle.HarnessUnmatched {
		t.Fatalf("harness=%+v err=%v", harness, err)
	}
	model, err := e.AuthorizeV2Model(context.Background(), sessionID, testAgent, "profile")
	if err != nil || model.Allow || model.ReasonCode != "model_not_assigned" {
		t.Fatalf("model decision=%+v err=%v", model, err)
	}
	e.ReconcileSession()
	if got, ok := sessions.Get(sessionID); !ok || got.Status != StatusLinked {
		t.Fatalf("linked session was incorrectly revoked: %+v exists=%t", got, ok)
	}
	if _, state, err := store.Check(testInstallation, testOrg, testWorkspace, now.Add(time.Second)); state != policybundle.Active || err != nil {
		t.Fatalf("store state=%s err=%v", state, err)
	}
}

func TestV2RefreshDoesNotPreserveRemovedRemoteIdentityByUserMembership(t *testing.T) {
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

// HAI-622-F: a v1 bundle can no longer become active, so the PDP never decides
// from one. Offering one to the store is rejected as unsupported, and every
// decision path then denies with the cold-start state instead of evaluating v1
// policies.
func TestV1BundleIsRejectedAndEveryDecisionPathStaysDenyOnly(t *testing.T) {
	useV2Fixtures(t)
	now := time.Now().UTC()
	sessions := NewSessions()
	sessionID, err := sessions.Create(Subject{UserID: "u-alice", Status: StatusLinked})
	if err != nil {
		t.Fatal(err)
	}
	e, store, _ := newTestEvaluator(t, now, nil, sessions)
	v1 := []byte(`{"schema":"kei.policy-bundle/v1","bundle_id":"b","bundle_version":1,"policy_revision":1,"issuer":"` + policybundle.Issuer + `",` +
		`"audience":{"installation_id":"` + testInstallation + `","org_id":"` + testOrg + `","workspace_id":"` + testWorkspace + `"},` +
		`"issued_at":"` + now.Format(time.RFC3339) + `","not_after":"` + now.Add(time.Hour).Format(time.RFC3339) + `"}`)
	if _, err := store.Activate(v1, testInstallation, testOrg, testWorkspace, now); !errors.Is(err, policybundle.ErrBundleUnsupported) {
		t.Fatalf("Activate(v1) err = %v, want ErrBundleUnsupported", err)
	}
	check := func(name string, d Decision, err error) {
		t.Helper()
		if err != nil || d.Allow || !strings.HasPrefix(string(d.ReasonCode), "policy_bundle_") || d.DenySource != "runtime_state" || d.BundleVersion != 0 {
			t.Fatalf("%s: decision=%+v err=%v, want a policy_bundle_* deny from runtime_state with no bundle version", name, d, err)
		}
	}
	d, err := e.Evaluate(context.Background(), Request{Session: sessionID, Tool: "search_web", Action: "tool:search_web"})
	check("Evaluate", d, err)
	g, err := e.EvaluateConnector(context.Background(), Request{Session: sessionID, Connector: &ConnectorTarget{ConnectorID: "conn-github-0001", Capability: "issue.read"}})
	check("EvaluateConnector", g.Decision, err)
	d, err = e.AuthorizeV2Model(context.Background(), sessionID, testAgent, "profile")
	check("AuthorizeV2Model", d, err)
}
func TestAuthorizeV2ModelDeniesWithoutABundleAndForEndedSessions(t *testing.T) {
	now := time.Now().UTC()
	sessions := NewSessions()
	sessionID, err := sessions.Create(Subject{UserID: "u-alice", Status: StatusLinked})
	if err != nil {
		t.Fatal(err)
	}
	endedSessionID, err := sessions.Create(Subject{UserID: "u-bob", Status: StatusLinked})
	if err != nil {
		t.Fatal(err)
	}
	sessions.EndID(endedSessionID)
	e, _, _ := newTestEvaluator(t, now, nil, sessions)
	if d, err := e.AuthorizeV2Model(context.Background(), sessionID, testAgent, "profile"); err != nil || d.Allow || d.ReasonCode != "policy_bundle_missing" {
		t.Fatalf("cold decision=%+v err=%v", d, err)
	}
	if d, err := e.AuthorizeV2Model(context.Background(), endedSessionID, testAgent, "profile"); err != nil || d.Allow || d.ReasonCode != ReasonSessionNotFound {
		t.Fatalf("ended session decision=%+v err=%v", d, err)
	}
}
