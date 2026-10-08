package policybundle

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

// activeFixtureWithSrc activates the v1 example bundle with the src_pattern of
// each named policy replaced.
func activeFixtureWithSrc(t *testing.T, srcByPolicy map[string]string) *Verified {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(fixtureBundle(t), &doc); err != nil {
		t.Fatal(err)
	}
	for _, p := range doc["policy_set"].(map[string]any)["policies"].([]any) {
		policy := p.(map[string]any)
		if src, ok := srcByPolicy[policy["id"].(string)]; ok {
			policy["src_pattern"] = src
		}
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	inst, org, ws := audience()
	v, err := store.Activate(b, inst, org, ws, fixtureNow())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSubjectRequiredOnlyForConnectorsAndSubjectScopedPolicies(t *testing.T) {
	scoped := activeFixtureWithSrc(t, nil)
	wildcard := activeFixtureWithSrc(t, map[string]string{"pol-baseline-search-wiki": "*"})
	for _, tc := range []struct {
		name   string
		bundle *Verified
		call   Call
		want   bool
	}{
		{"group-scoped local tool", scoped, Call{Tool: "search_wiki", Action: "tool:search_wiki"}, true},
		{"group-scoped local tool, caller user id ignored", scoped, Call{Tool: "search_wiki", UserID: "user-member-0001"}, true},
		{"wildcard local tool", wildcard, Call{Tool: "search_wiki", Action: "tool:search_wiki"}, false},
		{"wildcard local tool with a caller user id", wildcard, Call{Tool: "search_wiki", UserID: "user-member-0001"}, false},
		{"connector-bound tool under an agent-only policy", scoped, Call{Tool: "github.get_issue"}, true},
		{"wildcard deny decides before any subject policy", scoped, Call{Tool: "github.delete_repo", Action: "github:admin"}, false},
		{"unregistered tool", scoped, Call{Tool: "not_registered"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.bundle.SubjectRequired(tc.call); got != tc.want {
				t.Fatalf("SubjectRequired(%+v) = %t, want %t", tc.call, got, tc.want)
			}
		})
	}
}

// Without a subject, a wildcard local tool is decided by policy, not denied for
// the missing subject.
func TestWildcardLocalToolEvaluatesWithoutSubject(t *testing.T) {
	v := activeFixtureWithSrc(t, map[string]string{"pol-baseline-search-wiki": "*"})
	if d := v.Evaluate(Call{Tool: "search_wiki", Action: "tool:search_wiki"}, nil); d.Outcome != "allow" || d.PolicyID != "pol-baseline-search-wiki" {
		t.Fatalf("decision = %+v, want allow by pol-baseline-search-wiki", d)
	}
}
