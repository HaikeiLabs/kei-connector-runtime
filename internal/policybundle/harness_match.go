package policybundle

import (
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

// EvaluateHarness applies kei.harness-match/v1 to a harness tool call. It
// decodes the bundle's policy set and delegates to harnessmatch.Evaluate.
func (v *Verified) EvaluateHarness(c HarnessCall) (outcome, policyID, reason string) {
	set, err := v.decodePolicySet()
	if err != nil {
		return HarnessNotRenderable, "", HarnessReasonBundleInvalid
	}
	policies := make([]harnessmatch.Policy, len(set.Policies))
	for i, p := range set.Policies {
		policies[i] = harnessmatch.Policy{
			ID:      p.ID,
			Src:     p.Src,
			Dst:     p.Dst,
			Action:  p.Action,
			Enabled: true,
			Scope:   p.Scope.AgentID,
		}
	}
	result := harnessmatch.Evaluate(c, policies)
	return string(result.Outcome), result.PolicyID, result.Reason
}
