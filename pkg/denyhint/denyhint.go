// Package denyhint maps a deny reason_code to the concrete next step a
// developer should take. It is the single source of truth for the "hint"
// field carried next to reason_code on every deny response.
package denyhint

// hints is the stable reason_code -> next-step table. A code absent from the
// table gets no hint, so the response omits the field entirely rather than
// offering a generic or wrong command.
var hints = map[string]string{
	"no_matching_policy":     "Add a policy for this target: kei policy create --group <group> --allow <target> --workspace <workspace>",
	"tool_not_registered":    "Register the harness tools: kei harness sync --harness custom --manifest tools.json",
	"agent_not_assigned":     "Assign an agent to this runtime installation on the console Agents page so the runtime identity has a default agent.",
	"credential_unavailable": "Connect the provider on the console Connectors page (or deliver the credential) so the runtime can resolve the connector credential.",
	"subject_missing":        "Link the invoking user to this installation on the console Users page so a subject can be resolved.",
	"access_grant_expired":   "The access grant for this call has ended. Ask an admin for a new grant on the console Access grants page.",
	"no_grant_matched":       "No access grant covers this call. Ask an admin for a grant, or add a policy for this source and target.",
	"subject_unlinked":       "Link this identity to the installation: open the enrollment link when the response carries one, or link the user on the console Users page.",
	"preflight_required":     "Register the tool so the active policy bundle lists it (POST /v1/tools:register on the runtime socket, or kei harness sync --harness custom --manifest tools.json), then wait for the next bundle refresh.",
}

// Hint returns the next-step hint for a deny reason_code, or "" when the code
// is unknown.
func Hint(reasonCode string) string {
	return hints[reasonCode]
}
