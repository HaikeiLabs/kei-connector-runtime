package runtime

import (
	"context"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
)

// AuthorizeModel decides a model call for agentID and profileID against the
// refresher's identity and the cached v2 bundle (ADR-035 §6). It makes no
// control-plane request. Before the refresher has resolved the identity, or
// when the active bundle is not v2, the call is denied. The decision is
// audited like a socket authorize decision.
func (l *LocalPDP) AuthorizeModel(ctx context.Context, sessionID, agentID, profileID string) (pdp.Decision, error) {
	e := l.evaluator.Load()
	if e == nil || l.identity.Load() == nil {
		return pdp.Decision{ReasonCode: "policy_bundle_missing", DenySource: "runtime_state", Reason: "runtime identity is not resolved yet", BundleState: "cold"}, ctx.Err()
	}
	d, err := e.AuthorizeV2Model(ctx, sessionID, agentID, profileID)
	if err != nil {
		return d, err
	}
	if l.emit != nil {
		l.emit(l.decisionEventJSON(socketAuthorizeRequest{Schema: authorizeRequestSchema, Tool: "model:" + profileID, AgentID: agentID}, sessionID, d, ""))
	}
	return d, nil
}
