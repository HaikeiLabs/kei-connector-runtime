// Package denyhint maps a deny reason_code to the concrete next step a
// developer should take. It is the single source of truth for the "hint"
// field carried next to reason_code on every deny response.
package denyhint

// hints is the stable reason_code -> next-step table. A code absent from the
// table gets no hint, so the response omits the field entirely rather than
// offering a generic or wrong command.
var hints = map[string]string{
	"agent_not_bound_to_connector": "Bind the agent to the connector on the console Connectors page (kei-cli has no bind command).",
	"no_matching_policy":           "Add a policy for this target: kei policy create --group <group> --allow <target> --workspace <workspace>",
	"tool_not_registered":          "Register the harness tools: kei harness sync --harness custom --manifest tools.json",
	"agent_not_assigned":           "Assign an agent to this runtime installation on the console Agents page so the runtime identity has a default agent.",
	"credential_unavailable":       "Connect the provider on the console Connectors page (or deliver the credential) so the runtime can resolve the connector credential.",
	"subject_missing":              "Link the invoking user to this installation on the console Users page so a subject can be resolved.",
	"access_grant_expired":         "The access grant for this call has ended. Ask an admin for a new grant on the console Access grants page.",
	"no_grant_matched":             "No access grant covers this call. Ask an admin for a grant, or add a policy for this source and target.",
	"subject_unlinked":             "Link this identity to the installation: open the enrollment link when the response carries one, or link the user on the console Users page.",
	"preflight_required":           "Register the tool so the active policy bundle lists it (POST /v1/tools:register on the runtime socket, or kei harness sync --harness custom --manifest tools.json), then wait for the next bundle refresh.",
	"operation_plan_invalid":       "The connector tool arguments or resource do not match the active registered plan; re-sync the tool manifest and retry with valid arguments.",
}

// Hint returns the next-step hint for a deny reason_code, or "" when the code
// is unknown.
func Hint(reasonCode string) string {
	return hints[reasonCode]
}

var shellSyntaxHints = map[string]string{
	"parameter_expansion":   "Kei cannot safely evaluate parameter expansion. Reformulate only if you can preserve the command's meaning using supported shell syntax; the resulting command must still pass policy.",
	"command_substitution": "Kei cannot safely evaluate command substitution. Reformulate only if you can preserve the command's meaning using supported shell syntax; the resulting command must still pass policy.",
	"backtick_substitution": "Kei cannot safely evaluate backtick substitution. Reformulate only if you can preserve the command's meaning using supported shell syntax; the resulting command must still pass policy.",
	"unsupported_redirection": "This redirection is outside Kei's supported shell grammar. Use only a supported redirection if it preserves the intended behavior; the resulting command must still pass policy.",
	"unsupported_grouping": "This shell grouping construct is outside Kei's supported grammar. Reformulate only if you can preserve the command's meaning using supported syntax; the resulting command must still pass policy.",
	"unsupported_glob": "Kei cannot safely expand globs. Replace them only with an equivalent explicit argument list; the resulting command must still pass policy.",
	"unsupported_background": "Background shell execution is outside Kei's supported grammar. Use a foreground operation only if that preserves the intended behavior; it must still pass policy.",
	"tilde_expansion": "Kei cannot safely expand a tilde path. Use an explicit path only if it preserves the intended target; the resulting command must still pass policy.",
	"history_expansion": "Shell history expansion is outside Kei's supported grammar. Reformulate only if you can preserve the command's meaning using supported syntax; it must still pass policy.",
	"shell_comment": "Shell comments are outside Kei's supported grammar. Reformulate only if you can preserve the command's meaning using supported syntax; it must still pass policy.",
	"malformed_quoting": "Kei could not safely parse the quoting or escape syntax. Correct it without changing the intended command; the resulting command must still pass policy.",
	"control_character": "Control characters are outside Kei's supported shell grammar. Remove them only if the command's intended behavior is preserved; the resulting command must still pass policy.",
	"input_too_large": "The shell command exceeds Kei's parser limit. Reduce it without changing its intended behavior; the resulting command must still pass policy.",
	"invalid_command_structure": "Kei could not parse the command structure safely. Reformulate only within the documented grammar; the resulting command must still pass policy.",
	"invalid_input": "Kei could not parse the shell input safely. Correct the input without changing its intended behavior; the resulting command must still pass policy.",
}

// ShellSyntaxHint returns a static, bounded remediation for a parser category.
// Unknown values are omitted rather than echoed back to the caller.
func ShellSyntaxHint(syntaxCode string) string {
	return shellSyntaxHints[syntaxCode]
}
