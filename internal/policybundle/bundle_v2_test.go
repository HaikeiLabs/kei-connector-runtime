package policybundle

import (
	"encoding/json"
	"errors"
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
	if !v.SubjectSnapshotFresh(now) || v.SubjectSnapshotFresh(now.Add(30*time.Second)) {
		t.Fatal("snapshot freshness did not honor max_cache_seconds boundary")
	}
	if id, ok := v.LookupIdentity("discord", "ext-alice", now.Add(time.Second)); !ok || id.UserID != "user-alice" {
		t.Fatalf("fresh identity lookup = %+v, %v", id, ok)
	}
	if _, ok := v.LookupIdentity("discord", "ext-alice", now.Add(30*time.Second)); ok {
		t.Fatal("stale snapshot resolved a session identity")
	}
	staleDecision := v.EvaluateSessionAt(Call{Tool: "some.agent.tool"}, nil, nil, now.Add(30*time.Second))
	if staleDecision.Outcome != "deny" || staleDecision.ReasonCode != "subject_snapshot_stale" {
		t.Fatalf("stale snapshot decision = %+v", staleDecision)
	}

	for name, mutate := range map[string]func(map[string]any){
		"unknown envelope field": func(d map[string]any) { d["unexpected"] = true },
		"online mode": func(d map[string]any) {
			d["subject_resolution"] = map[string]any{"mode": "online", "max_cache_seconds": 30}
		},
		"zero cache age": func(d map[string]any) {
			d["subject_resolution"] = map[string]any{"mode": "bundle", "max_cache_seconds": 0}
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

func TestV2StoreMarksOverAgeSnapshotStale(t *testing.T) {
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
	if model.Outcome != "deny" || model.ReasonCode != "subject_snapshot_stale" {
		t.Fatalf("model action from aged v2 object = %+v", model)
	}
	harness, _, reason := fresh.EvaluateHarness(HarnessCall{Kind: "codex", Argv: []string{"git"}})
	if harness != HarnessNotRenderable {
		t.Fatalf("harness outcome=%s reason=%s", harness, reason)
	}
	verified, state, err := store.Check(v2Installation, v2Org, v2Workspace, now.Add(30*time.Second))
	if verified != nil || state != Stale || !errors.Is(err, ErrSubjectSnapshotStale) {
		t.Fatalf("stale check verified=%v state=%s err=%v", verified != nil, state, err)
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

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
