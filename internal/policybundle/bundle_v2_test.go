package policybundle

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	v2Installation = "inst-v2"
	v2Org          = "org-v2"
	v2Workspace    = "ws-v2"
)

func v2BundleDoc(now time.Time) map[string]any {
	return map[string]any{
		"schema": "kei.policy-bundle/v2", "bundle_id": "bundle-v2", "bundle_version": 2, "policy_revision": 7,
		"issuer": Issuer, "audience": map[string]any{"installation_id": v2Installation, "org_id": v2Org, "workspace_id": v2Workspace},
		"issued_at": now.UTC().Format(time.RFC3339Nano), "not_after": now.Add(12 * time.Hour).UTC().Format(time.RFC3339Nano),
		"refresh":            map[string]any{"poll_interval_seconds": 60, "stale_after_seconds": 300},
		"subject_resolution": map[string]any{"mode": "bundle", "max_cache_seconds": 30},
		"policy_set": map[string]any{
			"schema": "kei.policy-set/v2", "org_id": v2Org, "workspace_id": v2Workspace, "match_semantics": "kei.match/v2",
			"evaluation": map[string]any{"precedence": []string{"priority_desc", "deny_before_permit", "policy_id_asc"}, "checks": "per_capability_first_match_and", "default": "deny"},
			"tools":      []any{}, "checks": []any{}, "tool_policies": []any{},
			"harness_match_semantics": "kei.harness-match/v1", "harness_policies": []any{},
		},
		"agent_connector_bindings": []any{},
		"identities":               []any{map[string]any{"source": "discord", "external_id": "ext-alice", "user_id": "user-alice", "status": "linked", "groups": []string{"members"}}},
	}
}

func v2SchemaValidator(t *testing.T) func([]byte) error {
	t.Helper()
	load := func(name string) any {
		t.Helper()
		b, err := os.ReadFile("../../docs/contracts/" + name)
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
	if err := c.AddResource("https://schemas.haikeilabs.com/kei/policy-set-v2.schema.json", load("policy-set-v2.schema.json")); err != nil {
		t.Fatal(err)
	}
	if err := c.AddResource("https://schemas.haikeilabs.com/kei/policy-set-v1.schema.json", load("policy-set-v1.schema.json")); err != nil {
		t.Fatal(err)
	}
	if err := c.AddResource("https://schemas.haikeilabs.com/kei/policy-bundle-v2.schema.json", load("policy-bundle-v2.schema.json")); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("https://schemas.haikeilabs.com/kei/policy-bundle-v2.schema.json")
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

func TestValidateV2ClosedBundleAndSnapshotFreshness(t *testing.T) {
	previous := schemaValidatorV2
	SetV2SchemaValidator(v2SchemaValidator(t))
	t.Cleanup(func() { SetV2SchemaValidator(previous) })
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	marshal := func(doc map[string]any) []byte {
		t.Helper()
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	fixture, err := os.ReadFile("../../docs/contracts/examples/policy-bundle-v2.payload.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateV2(fixture, v2Installation, v2Org, v2Workspace, 1, now); err != nil {
		t.Fatalf("conformance fixture rejected: %v", err)
	}
	raw := marshal(v2BundleDoc(now))
	v, err := ValidateV2(raw, v2Installation, v2Org, v2Workspace, 1, now)
	if err != nil {
		t.Fatalf("ValidateV2: %v", err)
	}
	if !v.SubjectSnapshotFresh(now) || !v.SubjectSnapshotFresh(now.Add(30*time.Second)) {
		t.Fatal("snapshot freshness did not honor max_cache_seconds boundary")
	}
	if id, ok := v.LookupIdentity("discord", "ext-alice", now.Add(time.Second)); !ok || id.UserID != "user-alice" {
		t.Fatalf("fresh identity lookup = %+v, %v", id, ok)
	}
	if id, ok := v.LookupIdentity("discord", "ext-alice", now.Add(30*time.Second)); !ok || id.UserID != "user-alice" {
		t.Fatalf("identity lookup after 30s = %+v, %v", id, ok)
	}
	sessionDecision := v.EvaluateSessionAt(Call{Tool: "some.agent.tool"}, nil, nil, now.Add(30*time.Second))
	if sessionDecision.Outcome != "deny" || sessionDecision.ReasonCode != "preflight_required" {
		t.Fatalf("session decision = %+v", sessionDecision)
	}

	for name, mutate := range map[string]func(map[string]any){
		"unknown envelope field": func(d map[string]any) { d["unexpected"] = true },
		"online mode": func(d map[string]any) {
			d["subject_resolution"] = map[string]any{"mode": "online", "max_cache_seconds": 30}
		},
		"missing identities":     func(d map[string]any) { delete(d, "identities") },
		"unknown identity field": func(d map[string]any) { d["identities"].([]any)[0].(map[string]any)["email"] = "not-allowed" },
		"v1 policy set":          func(d map[string]any) { d["policy_set"].(map[string]any)["schema"] = "kei.policy-set/v1" },
	} {
		t.Run(name, func(t *testing.T) {
			doc := v2BundleDoc(now)
			mutate(doc)
			if _, err := ValidateV2(marshal(doc), v2Installation, v2Org, v2Workspace, 1, now); err == nil {
				t.Fatal("invalid v2 bundle accepted")
			}
		})
	}
}

func TestEvaluateHarnessUsesV2HarnessPolicies(t *testing.T) {
	previous := schemaValidatorV2
	SetV2SchemaValidator(v2SchemaValidator(t))
	t.Cleanup(func() { SetV2SchemaValidator(previous) })
	now := time.Now().UTC()
	doc := v2BundleDoc(now)
	doc["policy_set"].(map[string]any)["harness_policies"] = []any{map[string]any{
		"policy_id": "policy-shell-git", "name": "allow git", "src_pattern": "harness:codex", "dst_pattern": "shell:git", "action": "permit", "priority": 100,
		"scope": map[string]any{"org_id": v2Org, "workspace_id": v2Workspace, "agent_id": nil},
	}}
	v, err := ValidateV2(mustJSON(t, doc), v2Installation, v2Org, v2Workspace, 1, now)
	if err != nil {
		t.Fatalf("ValidateV2 harness policies: %v", err)
	}
	outcome, id, reason := v.EvaluateHarness(HarnessCall{Kind: "codex", Argv: []string{"git", "status"}})
	if outcome != HarnessPermit || id != "policy-shell-git" || reason != "" {
		t.Fatalf("EvaluateHarness = %q, %q, %q", outcome, id, reason)
	}
}

func TestV2StoreCheckAfterStalenessWindow(t *testing.T) {
	previous := schemaValidatorV2
	SetV2SchemaValidator(v2SchemaValidator(t))
	t.Cleanup(func() { SetV2SchemaValidator(previous) })
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	raw := mustJSON(t, v2BundleDoc(now))
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(raw, v2Installation, v2Org, v2Workspace, now); err != nil {
		t.Fatalf("activate v2 bundle: %v", err)
	}
	fresh, state, err := store.Check(v2Installation, v2Org, v2Workspace, now)
	if err != nil || fresh == nil || state != Active {
		t.Fatalf("fresh check verified=%v state=%s err=%v", fresh != nil, state, err)
	}
	model := fresh.EvaluateAction("model:invoke", "model:profile", "agent-1", nil)
	if model.Outcome != "deny" || model.ReasonCode != "agent_not_assigned" {
		t.Fatalf("model action from aged v2 object = %+v", model)
	}
	// HAI-452: the subject snapshot remains fresh after the old
	// max_cache_seconds window. Store.Check returns Active, not Stale.
	verified, state, err := store.Check(v2Installation, v2Org, v2Workspace, now.Add(30*time.Second))
	if verified == nil || state != Active || err != nil {
		t.Fatalf("check after 30s verified=%v state=%s err=%v", verified != nil, state, err)
	}
}

func TestValidateDispatchesV2WithoutChangingV1Validation(t *testing.T) {
	previous := schemaValidatorV2
	SetV2SchemaValidator(v2SchemaValidator(t))
	t.Cleanup(func() { SetV2SchemaValidator(previous) })
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	v, err := Validate(mustJSON(t, v2BundleDoc(now)), v2Installation, v2Org, v2Workspace, 1, now)
	if err != nil || v.Payload.Schema != "kei.policy-bundle/v2" {
		t.Fatalf("Validate dispatch for v2 = %+v, %v", v, err)
	}
}

func TestValidateV2AcceptsAbsentMaxCacheSeconds(t *testing.T) {
	previous := schemaValidatorV2
	SetV2SchemaValidator(v2SchemaValidator(t))
	t.Cleanup(func() { SetV2SchemaValidator(previous) })
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	doc := v2BundleDoc(now)
	doc["subject_resolution"] = map[string]any{"mode": "bundle"}
	if _, err := ValidateV2(mustJSON(t, doc), v2Installation, v2Org, v2Workspace, 1, now); err != nil {
		t.Fatalf("absent max_cache_seconds rejected: %v", err)
	}
}

func TestValidateV2AcceptsHighMaxCacheSeconds(t *testing.T) {
	previous := schemaValidatorV2
	SetV2SchemaValidator(v2SchemaValidator(t))
	t.Cleanup(func() { SetV2SchemaValidator(previous) })
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	doc := v2BundleDoc(now)
	doc["subject_resolution"] = map[string]any{"mode": "bundle", "max_cache_seconds": 3600}
	if _, err := ValidateV2(mustJSON(t, doc), v2Installation, v2Org, v2Workspace, 1, now); err != nil {
		t.Fatalf("max_cache_seconds=3600 rejected: %v", err)
	}
}

func TestSubjectSnapshotFreshWithAbsentMaxCacheSeconds(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	doc := v2BundleDoc(now)
	doc["subject_resolution"] = map[string]any{"mode": "bundle"}
	raw := mustJSON(t, doc)
	var payload Payload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	v := &Verified{Payload: payload, PayloadBytes: raw, Digest: "sha256:test"}
	// HAI-452: absent max_cache_seconds means the snapshot is fresh for
	// the bundle lifetime. SubjectSnapshotFresh returns true and identity
	// lookup succeeds even after 61s.
	if !v.SubjectSnapshotFresh(now.Add(61 * time.Second)) {
		t.Fatal("snapshot should be fresh with absent max_cache_seconds")
	}
	if _, ok := v.LookupIdentity("discord", "ext-alice", now.Add(61*time.Second)); !ok {
		t.Fatal("LookupIdentity should succeed after 61s with absent max_cache_seconds")
	}
}

func TestEvaluateActionNoStaleDenialAfterSixtyOneSeconds(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	doc := v2BundleDoc(now)
	doc["subject_resolution"] = map[string]any{"mode": "bundle", "max_cache_seconds": 30}
	raw := mustJSON(t, doc)
	var payload Payload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	v := &Verified{Payload: payload, PayloadBytes: raw, Digest: "sha256:test"}
	// HAI-452: SubjectSnapshotFresh ignores max_cache_seconds entirely
	// and returns true for any valid bundle. EvaluateAction never returns
	// subject_snapshot_stale — the snapshot is trusted.
	d := v.EvaluateAction("model:invoke", "model:profile", "agent-1", nil)
	if d.ReasonCode == "subject_snapshot_stale" {
		t.Fatalf("EvaluateAction returned stale denial for trusted snapshot: %+v", d)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
