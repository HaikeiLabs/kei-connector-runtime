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

func TestV1ValidatorStillRejectsV2Envelope(t *testing.T) {
	previous := schemaValidatorV2
	SetV2SchemaValidator(v2SchemaValidator(t))
	t.Cleanup(func() { SetV2SchemaValidator(previous) })
	if _, err := Validate(mustJSON(t, v2BundleDoc(time.Now().UTC())), v2Installation, v2Org, v2Workspace, 1, time.Now().UTC()); err != ErrBundleUnsupported {
		t.Fatalf("v1 Validate accepted v2 envelope: %v", err)
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
