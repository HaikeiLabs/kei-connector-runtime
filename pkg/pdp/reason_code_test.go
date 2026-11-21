package pdp

import "testing"

func TestDecisionReasonCodeIsTyped(t *testing.T) {
	var code ReasonCode = Decision{ReasonCode: ReasonAgentNotAssigned}.ReasonCode
	if code != "agent_not_assigned" {
		t.Fatalf("code = %q", code)
	}
}

func TestKnownReasonCodes(t *testing.T) {
	for _, c := range []ReasonCode{
		ReasonAgentMismatch, ReasonAgentNotAssigned,
		ReasonInvalidShellRequest, ReasonInvalidToolArgsDigest, ReasonNoMatchingPolicy,
		ReasonPolicyBundleInvalid, ReasonPolicyBundleMissing, ReasonPreflightRequired,
		ReasonRequestCanceled, ReasonSessionNotFound, ReasonSessionRequired,
		ReasonSessionRevalidationRequired, ReasonSubjectUnlinked, ReasonToolActionMismatch,
		ReasonToolNotRegistered, ReasonUnsupportedShellSyntax,
	} {
		if !c.Known() {
			t.Errorf("%q should be known", c)
		}
	}
	if ReasonCode("some_unknown_code").Known() {
		t.Error("an unlisted code must not be known")
	}
}
