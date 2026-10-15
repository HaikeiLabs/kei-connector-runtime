package runtime_test

import (
	"encoding/json"
	"testing"
	"time"

	connectorruntime "github.com/HaikeiLabs/kei-connector-runtime"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

// HAI-669 (R2): the local PDP answers the on_behalf_of exchanger's identity
// question from the bundle in force: the linked identity a user holds on a
// source (the user's Entra object id, source "entra").
func TestLocalPDPLinkedIdentityReadsTheBundleInForce(t *testing.T) {
	now := time.Now().UTC()
	doc := map[string]any{
		"schema": "kei.policy-bundle/v2", "bundle_id": "bundle-v2-linked-identity", "bundle_version": 43, "policy_revision": 7,
		"issuer":    "kei-policy-catalog",
		"audience":  map[string]any{"installation_id": "inst-fixture-0001", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001"},
		"issued_at": now.Format(time.RFC3339Nano), "not_after": now.Add(time.Hour).Format(time.RFC3339Nano),
		"refresh":            map[string]any{"poll_interval_seconds": 60, "stale_after_seconds": 300},
		"subject_resolution": map[string]any{"mode": "bundle", "max_cache_seconds": 30},
		"policy_set": map[string]any{
			"schema": "kei.policy-set/v2", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "match_semantics": "kei.match/v2",
			"evaluation": map[string]any{"precedence": []string{"priority_desc", "deny_before_permit", "policy_id_asc"}, "checks": "per_capability_first_match_and", "default": "deny"},
			"tools":      []any{}, "checks": []any{}, "tool_policies": []any{}, "harness_match_semantics": "kei.harness-match/v1", "harness_policies": []any{},
		},
		"agent_connector_bindings": []any{},
	}
	doc["identities"] = []any{
		map[string]any{"source": "discord", "external_id": "ext-v2-client-test", "user_id": "u-v2-client-test", "status": "linked"},
		map[string]any{"source": "entra", "external_id": "oid-v2-client-test", "user_id": "u-v2-client-test", "status": "linked"},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	l := keiruntime.NewLocalPDP(connectorruntime.Config{RuntimeToken: policyTestToken, RuntimeControlPlaneURL: "https://kei.example", RuntimeStateDir: dir}, nil)
	t.Cleanup(l.Close)
	if _, ok := l.LinkedIdentity("u-v2-client-test", "entra"); ok {
		t.Fatal("resolved an identity with no bundle in force")
	}
	activateBundle(t, dir, raw)
	l.SetIdentity(&keiruntime.Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001")})

	if oid, ok := l.LinkedIdentity("u-v2-client-test", "entra"); !ok || oid != "oid-v2-client-test" {
		t.Fatalf("entra identity = %q, %v", oid, ok)
	}
	if _, ok := l.LinkedIdentity("u-v2-client-test", "github"); ok {
		t.Fatal("resolved a source the user has no identity on")
	}
	if _, ok := l.LinkedIdentity("u-other", "entra"); ok {
		t.Fatal("resolved another user's identity")
	}
}
