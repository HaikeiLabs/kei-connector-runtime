package policybundle

import (
	"encoding/json"
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
	return v.toBundle().EvaluateV2Shell(argv, agentID, subject, now)
}

// EvaluateV2MCP applies ordered v2 harness policies to an MCP tool call
// using the authenticated session subject, the verified membership snapshot,
// and the calling harness kind (ADR-036 §4.6).
func (v *Verified) EvaluateV2MCP(slug, tool, agentID, harnessKind string, subject *SessionSubject, now time.Time) Decision {
	return v.toBundle().EvaluateV2MCP(slug, tool, agentID, harnessKind, subject, now)
}

func (v *Verified) EvaluateHarness(c HarnessCall) (outcome, policyID, reason string) {
	if v != nil && v.Payload.Schema == "kei.policy-bundle/v2" && !v.SubjectSnapshotFresh(time.Now()) {
		return HarnessNotRenderable, "", HarnessReasonBundleInvalid
	}
	var policies []harnessmatch.Policy
	if v.Payload.Schema == "kei.policy-bundle/v2" {
		// v2 carries harness policies under policy_set (kei#852).
		var set v2PolicySet
		if err := json.Unmarshal(v.Payload.PolicySet, &set); err != nil || set.HarnessMatchSemantics != "kei.harness-match/v1" {
			return HarnessNotRenderable, "", HarnessReasonBundleInvalid
		}
		policies = make([]harnessmatch.Policy, len(set.HarnessPolicies))
		for i, p := range set.HarnessPolicies {
			policies[i] = harnessmatch.Policy{ID: p.PolicyID, Src: p.Src, Dst: p.Dst, Action: p.Action, Enabled: true, Scope: p.Scope.AgentID}
		}
	} else {
		set, err := v.decodePolicySet()
		if err != nil {
			return HarnessNotRenderable, "", HarnessReasonBundleInvalid
		}
		policies = make([]harnessmatch.Policy, len(set.Policies))
		for i, p := range set.Policies {
			policies[i] = harnessmatch.Policy{ID: p.ID, Src: p.Src, Dst: p.Dst, Action: p.Action, Enabled: true, Scope: p.Scope.AgentID}
		}
	}
	result := harnessmatch.Evaluate(c, policies)
	return string(result.Outcome), result.PolicyID, result.Reason
}
