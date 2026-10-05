package policybundle

import (
	"strings"
	"time"
)

// DecisionPermit is the ADR-028 permit decision word, for callers that report
// a decision in that vocabulary.
const DecisionPermit = policyPermitAction

// Session subject statuses (ADR-026 G0, kei#681). The subject is established
// for a worker session by machine login plus kei or harness login and is held
// only in kei-proxy memory; it is never read from a per-call request.
const (
	SubjectLinked         = "linked"
	SubjectUnlinked       = "unlinked"
	SubjectPending        = "pending"
	SubjectRevoked        = "revoked"
	SubjectCrossWorkspace = "cross_workspace"
)

// SessionSubject is the acting user of the current worker session.
type SessionSubject struct {
	UserID string
	Email  string
	Status string
}

// Memberships answers which groups, org roles and workspace grant the bundle
// holds for a user. G0 puts memberships and grants in the bundle, but the
// kei.policy-bundle/v1 schema has no field for them yet, so a v1 bundle
// yields no Memberships and every membership-dependent source fails closed.
type Memberships interface {
	Lookup(userID string) (groups, roles []string, granted, known bool)
}

// BundleMemberships returns the memberships carried by the bundle, or nil
// when the bundle does not carry them (mode=online or no identities).
func BundleMemberships(v *Verified) Memberships {
	if len(v.Payload.Identities) == 0 {
		return nil
	}
	return &bundleMemberships{identities: v.Payload.Identities}
}

type bundleMemberships struct {
	identities []Identity
}

func (m *bundleMemberships) Lookup(userID string) (groups, roles []string, granted, known bool) {
	for _, id := range m.identities {
		if id.UserID != userID {
			continue
		}
		if !id.ExpireTime.IsZero() && !time.Now().Before(id.ExpireTime) {
			return nil, nil, false, false
		}
		known = true
		granted = id.Status == SubjectLinked
		return id.Groups, id.OrgRoles, granted, known
	}
	return nil, nil, false, false
}

// EvaluateSession decides a call with the in-memory session subject and no
// catalog round trip. Registry and agent checks come first, then the subject
// gate (a non-linked session denies before any policy), then the
// catalog-ordered policy walk. A human-source policy whose dst matches never
// falls through: without a session it denies subject_unlinked, and without
// bundle memberships a group or org source denies subject_pending.
func (v *Verified) EvaluateSession(call Call, subject *SessionSubject, members Memberships) Decision {
	call.UserID, call.Email = "", ""
	var pre Decision
	if call.ConnectorInvocation && call.Tool == "" {
		pre = v.EvaluateConnector(call, nil)
	} else {
		pre = v.Evaluate(call, nil)
	}
	switch pre.ReasonCode {
	case "policy_bundle_invalid", "tool_not_registered", "tool_action_mismatch", "agent_not_assigned", "agent_not_bound_to_connector":
		return pre
	}
	set, err := v.decodePolicySet()
	if err != nil {
		return invalidDecision()
	}
	if call.AgentID == "" {
		call.AgentID = defaultAgent(set)
	}
	var reg tool
	for _, t := range set.Tools {
		if (call.ConnectorInvocation && call.Tool != "" && t.Name == call.Tool && t.ConnectorID == call.ConnectorID && t.Capability == call.Capability) ||
			(call.ConnectorInvocation && call.Tool == "" && t.ConnectorID == call.ConnectorID && t.Capability == call.Capability) ||
			(!call.ConnectorInvocation && t.Name == call.Tool) {
			reg = t
			break
		}
	}
	if call.ConnectorInvocation {
		call.Tool = reg.Name
	} else {
		if call.ConnectorID == "" {
			call.ConnectorID = reg.ConnectorID
		}
		if call.Capability == "" {
			call.Capability = reg.Capability
		}
	}
	if subject != nil {
		if d, denied := subjectGate(subject); denied {
			return d
		}
		call.UserID, call.Email = subject.UserID, subject.Email
	}
	var groups, roles []string
	known := false
	if subject != nil && members != nil {
		var granted bool
		groups, roles, granted, known = members.Lookup(subject.UserID)
		if known && !granted {
			return Decision{Outcome: "deny", ReasonCode: "subject_revoked", Reason: "the bundle no longer grants the session subject"}
		}
	}
	for _, p := range set.Policies {
		if p.Scope.AgentID != nil && *p.Scope.AgentID != call.AgentID {
			continue
		}
		if !dstMatch(p.Dst, call, reg) {
			continue
		}
		if requiresSubject(p.Src) && !srcMatch(p.Src, Call{AgentID: call.AgentID}, nil, nil) {
			if subject == nil {
				return Decision{Outcome: "deny", ReasonCode: "subject_unlinked", Reason: "a matching policy names a person and there is no session subject"}
			}
			if needsMemberships(p.Src) && !known {
				return Decision{Outcome: "deny", ReasonCode: "subject_pending", Reason: "the bundle carries no memberships or grants for the session subject"}
			}
		}
		if !srcMatch(p.Src, call, groups, roles) {
			continue
		}
		if p.Action == "deny" {
			return Decision{Outcome: "deny", PolicyID: p.ID, ReasonCode: "policy_deny", Reason: "policy denied"}
		}
		if p.Action == policyPermitAction {
			return Decision{Outcome: "allow", PolicyID: p.ID}
		}
	}
	return Decision{Outcome: "deny", ReasonCode: "no_matching_policy", Reason: "no policy matched"}
}

func subjectGate(s *SessionSubject) (Decision, bool) {
	switch s.Status {
	case SubjectLinked:
		if s.UserID != "" {
			return Decision{}, false
		}
		return Decision{Outcome: "deny", ReasonCode: "subject_unlinked", Reason: "the session subject has no user id"}, true
	case SubjectPending:
		return Decision{Outcome: "deny", ReasonCode: "subject_pending", Reason: "the session subject's workspace access is pending"}, true
	case SubjectRevoked:
		return Decision{Outcome: "deny", ReasonCode: "subject_revoked", Reason: "the session subject was revoked"}, true
	case SubjectCrossWorkspace:
		return Decision{Outcome: "deny", ReasonCode: "subject_cross_workspace", Reason: "the session subject belongs to another workspace"}, true
	default:
		return Decision{Outcome: "deny", ReasonCode: "subject_unlinked", Reason: "the session subject is not linked"}, true
	}
}

// needsMemberships reports whether a source pattern can only be decided from
// group memberships or org roles (srcMatch also treats a bare name as a group).
func needsMemberships(pattern string) bool {
	if strings.HasPrefix(pattern, "group:") || strings.HasPrefix(pattern, "org:") {
		return true
	}
	return !strings.Contains(pattern, ":") && !strings.HasPrefix(pattern, "*")
}
