package shellpolicy

import (
	"strings"
	"testing"
)

// stageResult is a stand-in for a caller's decision type.
type stageResult struct {
	name    string
	verdict Verdict
}

func TestEvaluateCombinesWithDenyThenUnmatchedThenAllow(t *testing.T) {
	byCommand := map[string]stageResult{
		"allow1": {"allow1", Allow},
		"allow2": {"allow2", Allow},
		"unm1":   {"unm1", Unmatched},
		"unm2":   {"unm2", Unmatched},
		"deny1":  {"deny1", Deny},
		"deny2":  {"deny2", Deny},
	}
	tests := []struct {
		name   string
		stages string
		want   string
	}{
		{"single allow", "allow1", "allow1"},
		{"allow+allow reports first stage", "allow1 && allow2", "allow1"},
		{"allow+deny is deny", "allow1 && deny1", "deny1"},
		{"deny first, allow second", "deny1 ; allow1", "deny1"},
		{"allow+unmatched is unmatched", "allow1 | unm1", "unm1"},
		{"unmatched+allow is unmatched", "unm1 || allow1", "unm1"},
		{"unmatched+unmatched reports first", "unm1 && unm2", "unm1"},
		{"unmatched+deny is deny", "unm1 ; deny1", "deny1"},
		{"deny after allow and unmatched wins", "allow1 && unm1 | deny1", "deny1"},
		{"deny+deny reports first denier", "deny1 ; deny2", "deny1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stages [][]string
			for _, s := range strings.Split(strings.NewReplacer("&&", "|", "||", "|", ";", "|").Replace(tc.stages), "|") {
				stages = append(stages, strings.Fields(s))
			}
			got := Evaluate(stages, func(argv []string) (stageResult, Verdict) {
				r, ok := byCommand[argv[0]]
				if !ok {
					t.Fatalf("unexpected stage %v", argv)
				}
				return r, r.verdict
			})
			if got.name != tc.want {
				t.Fatalf("Evaluate(%q) = %q; want %q", tc.stages, got.name, tc.want)
			}
		})
	}
}

func TestEvaluateStopsAtFirstDeny(t *testing.T) {
	var seen []string
	Evaluate([][]string{{"a"}, {"b"}, {"c"}}, func(argv []string) (string, Verdict) {
		seen = append(seen, argv[0])
		if argv[0] == "b" {
			return "b", Deny
		}
		return argv[0], Allow
	})
	if got := strings.Join(seen, ","); got != "a,b" {
		t.Fatalf("evaluated stages %q; want a,b", got)
	}
}
