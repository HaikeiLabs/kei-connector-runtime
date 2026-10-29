package pdp

// ReasonCode is the typed reason a call was decided the way it was. On the
// wire it is still the plain string. Codes that come from the policy bundle
// evaluator pass through as ReasonCode(s); Known lists the ones the runtime
// itself produces or branches on.
type ReasonCode string

const (
	ReasonAgentMismatch               ReasonCode = "agent_mismatch"
	ReasonAgentNotAssigned            ReasonCode = "agent_not_assigned"
	ReasonAgentNotBoundToConnector    ReasonCode = "agent_not_bound_to_connector"
	ReasonInvalidShellRequest         ReasonCode = "invalid_shell_request"
	ReasonInvalidToolArgsDigest       ReasonCode = "invalid_tool_args_digest"
	ReasonNoMatchingPolicy            ReasonCode = "no_matching_policy"
	ReasonPolicyBundleInvalid         ReasonCode = "policy_bundle_invalid"
	ReasonPolicyBundleMissing         ReasonCode = "policy_bundle_missing"
	ReasonPreflightRequired           ReasonCode = "preflight_required"
	ReasonRequestCanceled             ReasonCode = "request_canceled"
	ReasonSessionNotFound             ReasonCode = "session_not_found"
	ReasonSessionRequired             ReasonCode = "session_required"
	ReasonSessionRevalidationRequired ReasonCode = "session_revalidation_required"
	ReasonSubjectUnlinked             ReasonCode = "subject_unlinked"
	ReasonToolActionMismatch          ReasonCode = "tool_action_mismatch"
	ReasonToolNotRegistered           ReasonCode = "tool_not_registered"
	ReasonUnsupportedShellSyntax      ReasonCode = "unsupported_shell_syntax"
)

var knownReasonCodes = map[ReasonCode]bool{
	ReasonAgentMismatch: true, ReasonAgentNotAssigned: true, ReasonAgentNotBoundToConnector: true,
	ReasonInvalidShellRequest: true, ReasonInvalidToolArgsDigest: true, ReasonNoMatchingPolicy: true,
	ReasonPolicyBundleInvalid: true, ReasonPolicyBundleMissing: true, ReasonPreflightRequired: true,
	ReasonRequestCanceled: true, ReasonSessionNotFound: true, ReasonSessionRequired: true,
	ReasonSessionRevalidationRequired: true, ReasonSubjectUnlinked: true, ReasonToolActionMismatch: true,
	ReasonToolNotRegistered: true, ReasonUnsupportedShellSyntax: true,
}

// Known reports whether c is one of the codes listed above.
func (c ReasonCode) Known() bool { return knownReasonCodes[c] }
