// Package denyhint maps a deny reason_code to the concrete next step a
// developer should take. It is the single source of truth for the "hint"
// field carried next to reason_code on every deny response.
package denyhint

// hints is the stable reason_code -> next-step table. A code absent from the
// table gets no hint, so the response omits the field entirely rather than
// offering a generic or wrong command.
var hints = map[string]string{
	"agent_not_bound_to_connector": "Bind the agent to the connector on the console Connectors page (kei-cli has no bind command).",
	"no_matching_policy":           "Add a policy for this source and target: kei policies create --name <name> --src-pattern <src> --dst-pattern <dst> --effect permit",
	"tool_not_registered":          "Register the harness tools: kei harness sync --harness custom --manifest tools.json",
	"agent_not_assigned":           "Assign an agent to this runtime installation on the console Agents page so the runtime identity has a default agent.",
	"credential_unavailable":       "Connect the provider on the console Connectors page (or deliver the credential) so the runtime can resolve the connector credential.",
	"subject_missing":              "Link the invoking user to this installation on the console Users page so a subject can be resolved.",
}

// Hint returns the next-step hint for a deny reason_code, or "" when the code
// is unknown.
func Hint(reasonCode string) string {
	return hints[reasonCode]
}
