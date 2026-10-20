package policybundle

import (
	"time"

	pol "github.com/HaikeiLabs/kei-connector-contracts/policy"
)

// The reasons a call the runtime's own rule matching did not cover can end
// with (ADR-038 §2, HAI-615). They are the shared policy package's reasons,
// carried through unchanged.
const (
	// ReasonAccessGrantExpired is the deny reason for a grant that matched
	// the call but has ended.
	ReasonAccessGrantExpired = "access_grant_expired"
	// ReasonNoGrantMatched is the deny reason for a bundle that carries
	// grants and none of them covers the call.
	ReasonNoGrantMatched = "no_grant_matched"
	// ReasonAccessGrantPermit is the reason on an allow that a live access
	// grant made.
	ReasonAccessGrantPermit = "access_grant_permit"
)

// v2ToolTarget is the typed target of one registered v2 tool
// ("tool:<name>"), the target an access grant names (ADR-038 §2).
func v2ToolTarget(name string) string {
	return "tool:" + name
}

// v2GrantDecision decides a call the runtime's own rule matching did not
// cover against the bundle's access grants (ADR-038 §2, HAI-615). The shared
// policy package decides: a live grant permits the call, a grant that has
// ended denies with access_grant_expired, and a bundle whose grants cover
// nothing denies with no_grant_matched.
//
// The rule set is empty on purpose. The runtime's own evaluation already ran
// and a matching rule decided the call; a grant only adds a permit where no
// rule matched, and it never overrides a deny. Translating the v2 checks
// into shared policy rules is a separate change.
//
// The second result is false when the bundle carries no grant at all, so the
// caller keeps its own no_matching_policy deny.
func (v *Verified) v2GrantDecision(target string, subject *SessionSubject, groups []string, now time.Time) (Decision, bool) {
	if v == nil || len(v.Payload.AccessGrants) == 0 || target == "" || subject == nil {
		return Decision{}, false
	}
	grants := make([]pol.AccessGrant, 0, len(v.Payload.AccessGrants))
	for _, grant := range v.Payload.AccessGrants {
		grants = append(grants, pol.AccessGrant{Principal: grant.Principal, Target: grant.Target, ExpireTime: grant.ExpireTime})
	}
	request := pol.Request{User: subject.UserID, Email: subject.Email, Groups: groups, Target: target}
	outcome := pol.DecideAt(nil, request, grants, now)
	switch outcome.Decision {
	case policyPermitAction:
		return Decision{
			Outcome:    "allow",
			PolicyID:   outcome.DecidedBy,
			ReasonCode: ReasonAccessGrantPermit,
			Reason:     "a live access grant permits the call",
		}, true
	case "no_match":
		reason := outcome.Reason
		if reason == "" {
			reason = ReasonNoGrantMatched
		}
		return Decision{Outcome: "deny", ReasonCode: reason, Reason: grantDenyReason(reason)}, true
	}
	return Decision{}, false
}

// v2GrantOrRule returns the decision for one call: the runtime's own rule
// matching decides it, and where no rule matched the bundle's access grants
// may still open it (ADR-038 §2). A rule that matched is never overridden,
// and a matching deny always wins.
func (v *Verified) v2GrantOrRule(decision Decision, target string, subject *SessionSubject, groups []string, now time.Time) Decision {
	if decision.Outcome == "allow" || decision.ReasonCode != "no_matching_policy" {
		return decision
	}
	if grant, ok := v.v2GrantDecision(target, subject, groups, now); ok {
		return grant
	}
	return decision
}

// grantDenyReason explains a grant deny in one line.
func grantDenyReason(code string) string {
	if code == ReasonAccessGrantExpired {
		return "the access grant for this call has ended"
	}
	return "no access grant covers this call"
}
