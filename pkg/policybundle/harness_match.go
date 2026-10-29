package policybundle

import (
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
func (v *Verified) EvaluateV2Shell(argv []string, agentID string, subject *SessionSubject, now time.Time) Decision {
	return v.toBundle().EvaluateV2Shell(argv, agentID, subject, now)
}

// EvaluateV2MCP applies ordered v2 harness policies to an MCP tool call
// using the authenticated session subject, the verified membership snapshot,
// and the calling harness kind (ADR-036 §4.6).
func (v *Verified) EvaluateV2MCP(slug, tool, agentID, harnessKind string, subject *SessionSubject, now time.Time) Decision {
	return v.toBundle().EvaluateV2MCP(slug, tool, agentID, harnessKind, subject, now)
}

// EvaluateHarness applies kei.harness-match/v1 to a harness tool call. It
// delegates to the contracts evaluator, which owns the precedence (ADR-038
// D-1 deny_overrides) and the harness condition (D-6 when {harness}), so the
// runtime cannot drift from the bundle contract.
func (v *Verified) EvaluateHarness(c HarnessCall) (outcome, policyID, reason string) {
	return v.toBundle().EvaluateHarness(c)
}
