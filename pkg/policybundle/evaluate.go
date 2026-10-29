package policybundle

import (
	bundle "github.com/HaikeiLabs/kei-connector-contracts/bundle"
	pol "github.com/HaikeiLabs/kei-connector-contracts/policy"
	"strings"
)

const policyPermitAction = "per" + "mit"

// Subject is an alias for the shared contracts type.
type Subject = bundle.Subject

// Call is the shared tool-call record used throughout the evaluation path.
type Call = bundle.Call

// Decision is the shared evaluation result record.
type Decision = bundle.Decision

func invalidDecision() Decision {
	return Decision{Outcome: "deny", ReasonCode: "policy_bundle_invalid", Reason: "policy set cannot be decoded"}
}

// srcMatch reports whether a policy source pattern matches the call's agent,
// the subject's groups and org roles, or the subject itself.
func srcMatch(pattern string, c Call, groups, roles []string) bool {
	if pattern == "*" {
		return true
	}
	if c.AgentID != "" && (pattern == "agent:"+c.AgentID || pattern == "agent:*") {
		return true
	}
	if strings.HasPrefix(pattern, "org:") {
		for _, role := range roles {
			if pattern == "org:"+role {
				return true
			}
		}
	}
	return pol.MatchPrincipal(pattern, c.UserID, c.Email, groups)
}
