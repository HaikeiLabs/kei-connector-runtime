package runtime

import (
	"context"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
)

// AuthorizeModel decides a model call for agentID and profileID against the
// refresher's identity and the cached v2 bundle (ADR-035 §6). It makes no
// control-plane request. v2 is false when the refresher has not resolved the
// identity yet or the active bundle is not v2; the caller then keeps the v1
// path. A v2 decision is audited like a socket authorize decision.
func (l *LocalPDP) AuthorizeModel(ctx context.Context, sessionID, agentID, profileID string) (d pdp.Decision, v2 bool, err error) {
	e := l.evaluator.Load()
	if e == nil || l.identity.Load() == nil {
		return pdp.Decision{}, false, ctx.Err()
	}
	d, v2, err = e.AuthorizeV2Model(ctx, sessionID, agentID, profileID)
	if err != nil || !v2 {
		return d, v2, err
	}
	if l.emit != nil {
		l.emit(l.decisionEventJSON(socketAuthorizeRequest{Schema: authorizeRequestSchema, Tool: "model:" + profileID, AgentID: agentID}, sessionID, d, nil))
	}
	return d, true, nil
}
