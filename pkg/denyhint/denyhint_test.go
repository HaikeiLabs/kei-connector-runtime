package denyhint

import "testing"

// TestHintCoversEveryKnownDenyCode asserts the stable table maps every known
// deny reason_code a developer can hit to a concrete next step.
func TestHintCoversEveryKnownDenyCode(t *testing.T) {
	known := []string{
		"agent_not_bound_to_connector",
		"no_matching_policy",
		"tool_not_registered",
		"agent_not_assigned",
		"credential_unavailable",
		"subject_missing",
		"access_grant_expired",
		"no_grant_matched",
	}
	for _, code := range known {
		if h := Hint(code); h == "" {
			t.Errorf("Hint(%q) = empty, want a non-empty next step", code)
		}
	}
}

// TestHintToolNotRegisteredNamesTheFullFix pins the exact hint for
// tool_not_registered: it must name the whole fix (register the harness tools
// with their manifest), not just a partial command.
func TestHintToolNotRegisteredNamesTheFullFix(t *testing.T) {
	const want = "Register the harness tools: kei harness sync --harness custom --manifest tools.json"
	if got := Hint("tool_not_registered"); got != want {
		t.Errorf("Hint(%q) = %q, want %q", "tool_not_registered", got, want)
	}
}

// TestHintUnknownCodeIsEmpty asserts codes outside the table (including the
// empty string) get no hint, so the response omits the field entirely.
func TestHintUnknownCodeIsEmpty(t *testing.T) {
	for _, code := range []string{"", "policy_bundle_missing", "no_session", "totally_unknown_code"} {
		if h := Hint(code); h != "" {
			t.Errorf("Hint(%q) = %q, want empty for codes outside the table", code, h)
		}
	}
}
