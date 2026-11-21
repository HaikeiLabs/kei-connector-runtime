package denyhint

import (
	"strings"
	"testing"
)

// TestHintCoversEveryKnownDenyCode asserts the stable table maps every known
// deny reason_code a developer can hit to a concrete next step.
func TestHintCoversEveryKnownDenyCode(t *testing.T) {
	known := []string{
		"no_matching_policy",
		"tool_not_registered",
		"agent_not_assigned",
		"credential_unavailable",
		"subject_missing",
		"access_grant_expired",
		"no_grant_matched",
		"subject_unlinked",
		"preflight_required",
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

// TestHintSubjectUnlinkedNamesTheFullFix pins the exact hint for
// subject_unlinked: it must tell the developer to link the user's identity
// through the enrollment link or console.
func TestHintSubjectUnlinkedNamesTheFullFix(t *testing.T) {
	const want = "Link this identity to the installation: open the enrollment link when the response carries one, or link the user on the console Users page."
	if got := Hint("subject_unlinked"); got != want {
		t.Errorf("Hint(%q) = %q, want %q", "subject_unlinked", got, want)
	}
}

// TestHintNoMatchingPolicyNamesTheFullFix pins the exact hint for
// no_matching_policy: it must suggest the current kei policy create syntax
// (not the deprecated kei policies create with --src-pattern/--dst-pattern).
func TestHintNoMatchingPolicyNamesTheFullFix(t *testing.T) {
	const want = "Add a policy for this target: kei policy create --group <group> --allow <target> --workspace <workspace>"
	if got := Hint("no_matching_policy"); got != want {
		t.Errorf("Hint(%q) = %q, want %q", "no_matching_policy", got, want)
	}
}

// TestHintPreflightRequiredNamesTheFullFix pins the exact hint for
// preflight_required: it must tell the developer to register the tool and
// wait for the bundle refresh.
func TestHintPreflightRequiredNamesTheFullFix(t *testing.T) {
	const want = "Register the tool so the active policy bundle lists it (POST /v1/tools:register on the runtime socket, or kei harness sync --harness custom --manifest tools.json), then wait for the next bundle refresh."
	if got := Hint("preflight_required"); got != want {
		t.Errorf("Hint(%q) = %q, want %q", "preflight_required", got, want)
	}
}

// TestHintUnknownCodeIsEmpty asserts codes outside the table (including the
// empty string) get no hint, so the response omits the field entirely.
func TestShellSyntaxHintsAreBoundedAndDoNotEchoInput(t *testing.T) {
	for _, code := range []string{
		"parameter_expansion", "command_substitution", "backtick_substitution",
		"unsupported_redirection", "unsupported_grouping", "unsupported_glob",
		"unsupported_background", "tilde_expansion", "history_expansion", "shell_comment",
		"malformed_quoting", "control_character", "input_too_large",
		"invalid_command_structure", "invalid_input",
	} {
		hint := ShellSyntaxHint(code)
		if hint == "" || len(hint) > 320 {
			t.Errorf("ShellSyntaxHint(%q) = %q, want bounded non-empty remediation", code, hint)
		}
		if strings.Contains(hint, code) || strings.Contains(hint, "command text") {
			t.Errorf("ShellSyntaxHint(%q) exposes parser input/category unnecessarily: %q", code, hint)
		}
	}
	if got := ShellSyntaxHint("unrecognized-user-value"); got != "" {
		t.Fatalf("unknown syntax category echoed/remediated: %q", got)
	}
}

func TestHintUnknownCodeIsEmpty(t *testing.T) {
	for _, code := range []string{"", "policy_bundle_missing", "no_session", "totally_unknown_code"} {
		if h := Hint(code); h != "" {
			t.Errorf("Hint(%q) = %q, want empty for codes outside the table", code, h)
		}
	}
}
