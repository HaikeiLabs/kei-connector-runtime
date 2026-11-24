package policybundle

import (
	"path"
	"sort"
	"strings"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/harnessmatch"
)

// HarnessCall is one tool call of a pre-built harness, described by the
// inputs kei.harness-match/v1 matches on (ADR-029 §1.2, §1.3).
type HarnessCall = harnessmatch.Call

// Harness outcomes (ADR-029 §1.5). Every non-permit, non-deny outcome carries a
// reason code (HarnessReason*).
const (
	HarnessPermit        = string(harnessmatch.OutcomePermit)
	HarnessDeny          = string(harnessmatch.OutcomeDeny)
	HarnessUnmatched     = string(harnessmatch.OutcomeUnmatched)
	HarnessNotRenderable = string(harnessmatch.OutcomeNotRenderable)
)

// Harness reason codes (ADR-029 §1.5 extension). Every non-permit, non-deny
// outcome carries one; permit and deny have no reason code.
const (
	HarnessReasonUnsupportedKind  = harnessmatch.ReasonUnsupportedKind
	HarnessReasonPathNotAbsolute  = harnessmatch.ReasonPathNotAbsolute
	HarnessReasonBundleInvalid    = harnessmatch.ReasonBundleInvalid
	HarnessReasonHumanSource      = harnessmatch.ReasonHumanSource
	HarnessReasonDstNotRenderable = harnessmatch.ReasonDstNotRenderable
	HarnessReasonEvaluateViaPDP   = harnessmatch.ReasonEvaluateViaPDP
)

// EvaluateV2Shell applies ordered v2 harness policies to one shell command
// using the authenticated session subject and the verified membership snapshot.
// The bundle-level evaluator is defined in kei-connector-contracts.
func (v *Verified) EvaluateV2Shell(argv []string, agentID string, subject *SessionSubject, now time.Time) Decision {
	return v.EvaluateV2ShellForKind("pi", argv, agentID, subject, now)
}

// EvaluateV2ShellForKind is EvaluateV2Shell for the harness kind whose shell
// the local PDP decides: harness:<kind> sources match that kind.
func (v *Verified) EvaluateV2ShellForKind(kind string, argv []string, agentID string, subject *SessionSubject, now time.Time) Decision {
	return v.toBundle().EvaluateV2ShellForKind(kind, argv, agentID, subject, now)
}

// EvaluateV2MCP applies ordered v2 harness policies to an MCP tool call
// using the authenticated session subject, the verified membership snapshot,
// and the calling harness kind (ADR-036 §4.6).
func (v *Verified) EvaluateV2MCP(slug, tool, agentID, harnessKind string, subject *SessionSubject, now time.Time) Decision {
	return v.toBundle().EvaluateV2MCP(slug, tool, agentID, harnessKind, subject, now)
}

// EvaluateV2HarnessPath evaluates path-destination harness policies for one
// registered Pi filesystem operation. Its result is an additional deny gate:
// a permit here never grants the tool call by itself.
func (v *Verified) EvaluateV2HarnessPath(resourcePath, agentID string, subject *SessionSubject, now time.Time) Decision {
	if !path.IsAbs(resourcePath) || path.Clean(resourcePath) != resourcePath {
		return Decision{Outcome: "deny", ReasonCode: "invalid_resource_path", Reason: "the Pi filesystem resource path must be absolute and canonical"}
	}
	if decision, denied := v.v2SubjectDenial(subject, now); denied {
		return decision
	}
	members := BundleMembershipsAt(v, now)
	if members == nil {
		return Decision{Outcome: "deny", ReasonCode: "subject_pending", Reason: "the verified membership snapshot is unavailable"}
	}
	groups, roles, granted, known := members.Lookup(subject.UserID)
	if !known || !granted {
		return Decision{Outcome: "deny", ReasonCode: "subject_pending", Reason: "the verified membership snapshot does not grant the session subject"}
	}
	if subject.Source == "installation_owner" && v.Payload.Subject != nil && v.Payload.Subject.UserID == subject.UserID {
		groups = v.Payload.Subject.Groups
	}
	var set v2PolicySet
	if err := strictJSON(v.Payload.PolicySet, &set); err != nil || set.HarnessMatchSemantics != "kei.harness-match/v1" {
		return invalidDecision()
	}
	call := harnessmatch.Call{Kind: "pi", AgentID: agentID, Path: resourcePath}
	matching := make([]v2HarnessPolicy, 0)
	for _, policy := range set.HarnessPolicies {
		if !strings.HasPrefix(policy.Dst, "path:") || (policy.Action != policyPermitAction && policy.Action != "deny") {
			continue
		}
		if !v2ScopeMatches(policy.Scope, agentID, v.Payload.Audience.OrgID, v.Payload.Audience.WorkspaceID) || !policy.whenHolds(call.Kind) {
			continue
		}
		if matched, renderable := harnessmatch.MatchDst(policy.Dst, call); !matched || !renderable {
			continue
		}
		if !harnessPolicySourceMatches(policy.Src, call, subject, groups, roles) {
			continue
		}
		matching = append(matching, policy)
	}
	if len(matching) == 0 {
		return Decision{Outcome: "deny", ReasonCode: "no_matching_policy", Reason: "no path policy matched"}
	}
	sort.Slice(matching, func(i, j int) bool {
		if !set.denyOverrides() && matching[i].Priority != matching[j].Priority {
			return matching[i].Priority > matching[j].Priority
		}
		if matching[i].Action != matching[j].Action {
			return matching[i].Action == "deny"
		}
		return matching[i].PolicyID < matching[j].PolicyID
	})
	winner := matching[0]
	if winner.Action == "deny" {
		return Decision{Outcome: "deny", PolicyID: winner.PolicyID, ReasonCode: "policy_deny", Reason: "policy denied"}
	}
	return Decision{Outcome: "allow", PolicyID: winner.PolicyID, ReasonCode: "policy_permit"}
}

func harnessPolicySourceMatches(pattern string, call harnessmatch.Call, subject *SessionSubject, groups, roles []string) bool {
	if pattern == "harness:*" {
		return true
	}
	if strings.HasPrefix(pattern, "harness:") {
		return strings.TrimPrefix(pattern, "harness:") == call.Kind
	}
	return srcMatch(pattern, Call{AgentID: call.AgentID, UserID: subject.UserID, Email: subject.Email}, groups, roles)
}

// EvaluateHarness applies kei.harness-match/v1 to a harness tool call. It
// delegates to the contracts evaluator, which owns the precedence (ADR-038
// D-1 deny_overrides) and the harness condition (D-6 when {harness}), so the
// runtime cannot drift from the bundle contract.
func (v *Verified) EvaluateHarness(c HarnessCall) (outcome, policyID, reason string) {
	return v.toBundle().EvaluateHarness(c)
}
