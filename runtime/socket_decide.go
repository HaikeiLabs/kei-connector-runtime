package runtime

// The decision half of the local PDP: how a /v1/authorize or
// /v1/credentials:release request becomes a pdp.Decide target and a decision.

import (
	"context"
	"strings"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
)

// decideAuthorize computes the /v1/authorize decision for req in sessionID.
// It is shared by /v1/authorize and /v1/credentials:release so the two always
// agree. auditTrustedAgent is true when the decision used the runtime
// identity's default agent (the audit records that agent instead of the
// request's). The error is non-nil only when ctx is done.
func (l *LocalPDP) decideAuthorize(ctx context.Context, sessionID string, req socketAuthorizeRequest) (d pdp.Decision, auditTrustedAgent, unmatched bool, err error) {
	d = pdp.Decision{ReasonCode: pdp.ReasonPolicyBundleMissing, DenySource: "runtime_state", Reason: "runtime identity is not resolved yet", BundleState: "cold"}
	shellKind, isShell := l.shellKindForTool(req.Tool)
	auditTrustedAgent = isShell
	if sessionID == "" {
		d = pdp.Decision{ReasonCode: pdp.ReasonSessionRequired, DenySource: "identity", Reason: "a named session is required"}
		return d, auditTrustedAgent, false, nil
	}
	if !l.Sessions.Exists(sessionID) {
		d = pdp.Decision{ReasonCode: pdp.ReasonSessionNotFound, DenySource: "identity", Reason: "the session does not exist or has ended"}
		return d, auditTrustedAgent, false, nil
	}
	e := l.evaluator.Load()
	if e == nil {
		return d, auditTrustedAgent, false, nil
	}
	if sub, ok := l.Sessions.Get(sessionID); ok && sub.SubjectKind == "service_principal" {
		if _, valid := e.BundleServicePrincipalIdentity(sub.UserID, l.trustedAgentID()); !valid {
			return pdp.Decision{ReasonCode: pdp.ReasonSubjectUnlinked, DenySource: "identity", Reason: "the principal is no longer present for this agent", BundleState: "ready"}, auditTrustedAgent, false, nil
		}
	}
	target := pdp.Target{Tool: req.Tool, Action: req.Action, Resource: req.Resource}
	if req.Connector != nil {
		target.Connector = &pdp.ConnectorTarget{ConnectorID: req.Connector.ConnectorID, Capability: req.Connector.Capability}
	}
	if req.Tool != "" && req.Connector != nil {
		return l.decideHarnessToolForTarget(ctx, sessionID, req)
	}
	switch {
	// A shell tool is one the bundle's harness kind registry names for a kind
	// the local PDP decides (the generic "shell" until the bundle carries a
	// registry).
	case isShell:
		if !validArgumentDigest(req.ToolArgsDigest) {
			return pdp.Decision{ReasonCode: pdp.ReasonInvalidToolArgsDigest, DenySource: "policy", Reason: "shell authorization requires a SHA-256 argument digest"}, auditTrustedAgent, false, nil
		}
		// The caller's optional AgentID is dropped; Decide uses the
		// authenticated runtime identity's assigned default.
		target = pdp.Target{Shell: req.ShellCommand, ShellKind: shellKind}
		req.AgentID = ""
	case req.ShellCommand != "":
		return pdp.Decision{ReasonCode: pdp.ReasonInvalidShellRequest, DenySource: "policy", Reason: "shell command is only valid for a shell tool"}, auditTrustedAgent, false, nil
	}
	res, err := e.Decide(ctx, pdp.DecideRequest{
		Session: sessionID, Target: target, AgentID: req.AgentID,
		TrustedAgent: l.trustedAgentID(), OwnerSession: l.isOwnerSession(sessionID),
	})
	return res.Decision, auditTrustedAgent || res.AuditTrustedAgent, res.Unmatched, err
}

// shellKindForTool names the harness kind whose shell command line the local
// PDP decides when tool is that kind's shell tool. Before an evaluator exists
// the generic "shell" tool is the only one.
func (l *LocalPDP) shellKindForTool(tool string) (string, bool) {
	if e := l.evaluator.Load(); e != nil {
		return e.ShellKindForTool(tool)
	}
	if tool == "shell" {
		return "pi", true
	}
	return "", false
}

func (l *LocalPDP) isOwnerSession(sessionID string) bool {
	if sessionID == "" || sessionID == pdp.DefaultSession {
		return false
	}
	l.ownerMu.RLock()
	defer l.ownerMu.RUnlock()
	return l.ownerID == sessionID && !l.ownerUnavailable
}

// decideHarnessToolForTarget authorizes a harness-executed tool against one
// exact connector/capability/resource tuple. Connector-binding tools remain on
// the complete-plan path and are never admitted here.
func (l *LocalPDP) decideHarnessToolForTarget(ctx context.Context, sessionID string, req socketAuthorizeRequest) (pdp.Decision, bool, bool, error) {
	deny := func(code pdp.ReasonCode, reason string) (pdp.Decision, bool, bool, error) {
		return pdp.Decision{ReasonCode: code, DenySource: "policy", Reason: reason, BundleState: "ready"}, true, false, nil
	}
	if req.Resource == "" {
		return deny("target_required", "harness connector authorization requires an exact resource")
	}
	if sessionID == "" || !l.Sessions.Exists(sessionID) {
		return deny(pdp.ReasonSessionNotFound, "target authorization requires a live named session")
	}
	e, identity := l.evaluator.Load(), l.identity.Load()
	if e == nil || identity == nil {
		return deny(pdp.ReasonPolicyBundleMissing, "runtime identity or policy bundle is unavailable")
	}
	trusted := identity.AgentID
	if trusted == "" || (req.AgentID != "" && req.AgentID != trusted) {
		return deny("agent_mismatch", "the request agent is not this installation's default agent")
	}
	verified, ok := e.Bundle()
	if !ok || verified.Payload.Schema != "kei.policy-bundle/v2" {
		return deny("policy_bundle_invalid", "target authorization requires a verified v2 bundle")
	}
	connector, ok := verified.Connector(req.Connector.ConnectorID)
	if !ok {
		return deny("connector_not_registered", "connector is not described in the verified v2 bundle")
	}
	capabilityFound := false
	for _, capability := range connector.Capabilities {
		if capability.Name == req.Connector.Capability {
			capabilityFound = true
			break
		}
	}
	if !capabilityFound {
		return deny("capability_not_registered", "capability is not declared for the connector")
	}
	d, err := e.AuthorizeV2HarnessToolForTarget(ctx, pdp.Request{Session: sessionID, Tool: req.Tool, AgentID: trusted}, req.Connector.ConnectorID, req.Connector.Capability, req.Resource)
	return d, true, false, err
}

// decideCredentialReleaseV2 authorizes one exact tool/connector/capability/
// resource tuple using the trusted installation agent and named session.
func (l *LocalPDP) decideCredentialReleaseV2(ctx context.Context, sessionID string, req socketAuthorizeRequest) (pdp.Decision, bool) {
	denied := func(code pdp.ReasonCode, reason string) (pdp.Decision, bool) {
		return pdp.Decision{ReasonCode: code, DenySource: "policy", Reason: reason, BundleState: "ready"}, true
	}
	if sessionID == pdp.DefaultSession || !l.Sessions.Exists(sessionID) {
		return denied(pdp.ReasonSessionNotFound, "v2 credential release requires a live named session")
	}
	e, identity := l.evaluator.Load(), l.identity.Load()
	if e == nil || identity == nil {
		return denied("policy_bundle_missing", "runtime identity or policy bundle is unavailable")
	}
	if sub, ok := l.Sessions.Get(sessionID); ok && sub.SubjectKind == "service_principal" {
		if _, valid := e.BundleServicePrincipalIdentity(sub.UserID, identity.AgentID); !valid {
			return denied("subject_unlinked", "the principal is no longer present for this agent")
		}
	}
	trusted := identity.AgentID
	if trusted == "" || (req.AgentID != "" && req.AgentID != trusted) {
		return denied("agent_mismatch", "the request agent is not this installation's default agent")
	}
	verified, ok := e.Bundle()
	if !ok || verified.Payload.Schema != "kei.policy-bundle/v2" {
		return denied("policy_bundle_invalid", "tool-bound credential release requires a verified v2 bundle")
	}
	connector, ok := verified.Connector(req.Connector.ConnectorID)
	if !ok {
		return denied("connector_not_registered", "connector is not described in the verified v2 bundle")
	}
	if connector.AccountModel != "shared" && connector.AccountModel != "per_user" {
		return denied("account_model_not_supported", "tool-bound release requires a shared or per_user connector")
	}
	if connector.AccountModel == "per_user" {
		if subject, ok := l.Sessions.Get(sessionID); !ok || subject.SubjectKind == "service_principal" || subject.UserID == "" {
			return denied("account_model_not_supported", "per_user credentials require a user-bound session")
		}
	}
	capabilityFound := false
	for _, capability := range connector.Capabilities {
		if capability.Name == req.Connector.Capability {
			capabilityFound = true
			break
		}
	}
	if !capabilityFound {
		return denied("capability_not_registered", "capability is not declared for the connector")
	}
	d, err := e.AuthorizeV2HarnessToolForTarget(ctx, pdp.Request{
		Session: sessionID, Tool: req.Tool, AgentID: trusted,
	}, req.Connector.ConnectorID, req.Connector.Capability, req.Resource)
	if err != nil {
		return pdp.Decision{ReasonCode: pdp.ReasonRequestCanceled, DenySource: "runtime_state", Reason: "request canceled", BundleState: "ready"}, true
	}
	return d, true
}

// trustedAgentID is the default agent of the authenticated runtime identity,
// or "" when none is assigned. It never comes from a caller's request.
func (l *LocalPDP) trustedAgentID() string {
	if identity := l.identity.Load(); identity != nil {
		return identity.AgentID
	}
	return ""
}

func validArgumentDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	for _, r := range value[len("sha256:"):] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}
