package policybundle

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

// testdata/catalog-v2-bundle.json is produced by kei-policy-catalog's v2
// builder (CompileStoredPolicyBundlePolicies, BuildPolicySetV2 and
// BuildPolicyBundleV2 with an installation subject; HaikeiLabs/kei-policy-catalog#224).
// The runtime must accept the catalog's emitted v2 shape (kei#852): harness
// policies under policy_set and the optional top-level subject.
const (
	catalogV2Installation = "20000000-0000-0000-0000-000000000001"
	catalogV2Org          = "20000000-0000-0000-0000-000000000002"
	catalogV2Workspace    = "20000000-0000-0000-0000-000000000003"
)

func catalogV2Fixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/catalog-v2-bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCatalogV2BundleFixtureValidatesAndDecodes(t *testing.T) {
	validate := v2SchemaValidator(t)
	previous := schemaValidatorV2
	SetV2SchemaValidator(validate)
	t.Cleanup(func() { SetV2SchemaValidator(previous) })
	raw := catalogV2Fixture(t)

	if err := validate(raw); err != nil {
		t.Fatalf("runtime v2 schema rejects the catalog's v2 bundle: %v", err)
	}
	now := time.Date(2026, 10, 9, 12, 0, 10, 0, time.UTC)
	v, err := ValidateV2(raw, catalogV2Installation, catalogV2Org, catalogV2Workspace, 1, now)
	if err != nil {
		t.Fatalf("ValidateV2(catalog fixture): %v", err)
	}
	s := v.Payload.Subject
	if s == nil || s.UserID != "20000000-0000-0000-0000-000000000005" || s.Email != "creator@example.test" || len(s.Groups) != 2 || s.Groups[0] != "members" || s.Groups[1] != "release_eng" {
		t.Fatalf("subject = %+v", s)
	}
	// EvaluateHarness checks snapshot freshness against the wall clock, so
	// evaluate a copy of the fixture re-stamped as issued now.
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	wall := time.Now().UTC()
	doc["issued_at"], doc["not_after"] = wall.Format(time.RFC3339Nano), wall.Add(time.Hour).Format(time.RFC3339Nano)
	restamped, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if v, err = ValidateV2(restamped, catalogV2Installation, catalogV2Org, catalogV2Workspace, 1, wall); err != nil {
		t.Fatalf("ValidateV2(re-stamped fixture): %v", err)
	}
	outcome, id, reason := v.EvaluateHarness(HarnessCall{Kind: "codex", Argv: []string{"gh", "pr", "view"}})
	if outcome != HarnessPermit || id != "20000000-0000-0000-0000-000000000012" || reason != "" {
		t.Fatalf("EvaluateHarness(codex gh) = %q, %q, %q", outcome, id, reason)
	}
	// group:/user: sources are human sources: the PEP never resolves them
	// from a harness call; renderers apply them against the subject.
	if outcome, _, reason := v.EvaluateHarness(HarnessCall{Kind: "codex", Skill: "deploy"}); outcome == HarnessPermit || outcome == HarnessDeny {
		t.Fatalf("EvaluateHarness(skill deploy) = %q (%s), want no decision for a group: source", outcome, reason)
	}
}

func TestCatalogV2BundleRejectsTopLevelHarnessPolicies(t *testing.T) {
	validate := v2SchemaValidator(t)
	previous := schemaValidatorV2
	SetV2SchemaValidator(validate)
	t.Cleanup(func() { SetV2SchemaValidator(previous) })
	var doc map[string]any
	if err := json.Unmarshal(catalogV2Fixture(t), &doc); err != nil {
		t.Fatal(err)
	}
	doc["harness_policies"] = doc["policy_set"].(map[string]any)["harness_policies"]
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 9, 12, 0, 10, 0, time.UTC)
	if _, err := ValidateV2(raw, catalogV2Installation, catalogV2Org, catalogV2Workspace, 1, now); !errors.Is(err, ErrBundleUnsupported) {
		t.Fatalf("pre-#852 top-level harness_policies: err = %v, want ErrBundleUnsupported", err)
	}
	delete(doc, "harness_policies")
	doc["subject"].(map[string]any)["unexpected"] = true
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateV2(raw, catalogV2Installation, catalogV2Org, catalogV2Workspace, 1, now); !errors.Is(err, ErrBundleUnsupported) {
		t.Fatalf("unknown subject field: err = %v, want ErrBundleUnsupported", err)
	}
}
