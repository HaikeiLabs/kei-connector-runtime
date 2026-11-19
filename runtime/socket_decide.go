package runtime

// The decision half of the local PDP: how a /v1/authorize or
// /v1/credentials:release request becomes a pdp.Decide target and a decision.

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

// decideAuthorize computes the /v1/authorize decision for req in sessionID.
// It is shared by /v1/authorize and /v1/credentials:release so the two always
// agree. auditTrustedAgent is true when the decision used the runtime
// identity's default agent (the audit records that agent instead of the
// request's). The error is non-nil only when ctx is done.
func (l *LocalPDP) decideAuthorize(ctx context.Context, sessionID string, req socketAuthorizeRequest) (d pdp.Decision, auditTrustedAgent, unmatched bool, err error) {
	l.refreshIdentityForBundle(ctx)
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
	if strings.HasPrefix(req.Tool, "mcp:") {
		return l.decideMCPTool(ctx, sessionID, req)
	}
	target := pdp.Target{Tool: req.Tool, Action: req.Action, Resource: req.Resource}
	if req.Connector != nil {
		target.Connector = &pdp.ConnectorTarget{ConnectorID: req.Connector.ConnectorID, Capability: req.Connector.Capability}
	}
	if len(req.ToolArgs) > 0 {
		return l.decideV2ConnectorPlan(ctx, sessionID, req)
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

// decideV2ConnectorPlan evaluates a connector_binding tool's complete plan
// using the locally held, verified tool manifest and runtime identity.
func (l *LocalPDP) decideV2ConnectorPlan(ctx context.Context, sessionID string, req socketAuthorizeRequest) (pdp.Decision, bool, bool, error) {
	deny := func(code pdp.ReasonCode, reason string) (pdp.Decision, bool, bool, error) {
		return pdp.Decision{ReasonCode: code, DenySource: "policy", Reason: reason, BundleState: "ready"}, true, false, nil
	}
	if req.Connector != nil {
		return deny("operation_plan_invalid", "connector_binding authorization derives its connector from the registered plan")
	}
	e, identity := l.evaluator.Load(), l.identity.Load()
	if e == nil || identity == nil {
		return deny(pdp.ReasonPolicyBundleMissing, "runtime identity or policy bundle is unavailable")
	}
	trusted := identity.AgentID
	if trusted == "" || (req.AgentID != "" && req.AgentID != trusted) {
		return deny("agent_mismatch", "the request agent is not this installation's default agent")
	}
	contextData := req.ToolContext
	if len(contextData) == 0 {
		contextData = json.RawMessage(`{}`)
	}
	d, err := e.AuthorizeV2ConnectorPlan(ctx, pdp.Request{Session: sessionID, Tool: req.Tool, AgentID: trusted}, req.ToolArgs, contextData)
	return d, true, false, err
}

// decideMCPTool evaluates the canonical mcp:<connector-slug>.<upstream-tool>
// target against a verified approved manifest and canonical MCP policy. Pi's
// adapter resolves generated names to this identity before calling the socket.
func (l *LocalPDP) decideMCPTool(ctx context.Context, sessionID string, req socketAuthorizeRequest) (pdp.Decision, bool, bool, error) {
	deny := func(code pdp.ReasonCode, reason string) (pdp.Decision, bool, bool, error) {
		return pdp.Decision{ReasonCode: code, DenySource: "policy", Reason: reason, BundleState: "ready"}, true, false, nil
	}
	if req.Action != "" || req.Resource != "" || req.Connector != nil || req.ShellCommand != "" {
		return deny("invalid_mcp_request", "canonical MCP authorization accepts only an exact tool target")
	}
	if !validArgumentDigest(req.ToolArgsDigest) {
		return deny(pdp.ReasonInvalidToolArgsDigest, "MCP authorization requires a SHA-256 argument digest")
	}
	if req.Framework == "" {
		return deny("invalid_mcp_request", "MCP authorization requires a harness identity")
	}
	if !validMCPManifestHash(req.MCPManifestHash) {
		return deny("invalid_mcp_request", "MCP authorization requires the hash of the discovered tool manifest")
	}
	target := strings.TrimPrefix(req.Tool, "mcp:")
	slug, tool, ok := strings.Cut(target, ".")
	if !ok || !validMCPSlug(slug) || !validMCPToolName(tool) {
		return deny("invalid_mcp_request", "MCP target must name an exact connector slug and tool")
	}
	trusted := l.trustedAgentID()
	if trusted == "" {
		return deny("agent_mismatch", "runtime installation has no default agent")
	}
	verified, ok := l.evaluator.Load().Bundle()
	if !ok {
		return deny(pdp.ReasonPolicyBundleMissing, "verified policy bundle is unavailable")
	}
	connector, ok := verified.MCPConnector(slug)
	if !ok || connector.MCP == nil {
		return deny("connector_not_registered", "MCP connector is not in the verified policy bundle")
	}
	if connector.MCP.ApprovedManifestHash == "" {
		return deny("mcp_manifest_unapproved", "the connector has no approved MCP tool manifest")
	}
	if req.MCPManifestHash != connector.MCP.ApprovedManifestHash {
		return deny("mcp_manifest_drift", "the discovered MCP tool manifest differs from the approved manifest")
	}
	d, err := l.evaluator.Load().AuthorizeV2MCP(ctx, sessionID, slug, tool, trusted, req.Framework)
	return d, true, false, err
}

func validMCPSlug(value string) bool {
	if len(value) < 2 || len(value) > 48 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, r := range value[1:] {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_') {
			return false
		}
	}
	return true
}

func validMCPToolName(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '.' || r == '-') {
			return false
		}
	}
	return true
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

func (l *LocalPDP) isV2ConnectorTool(name string) bool {
	if l == nil {
		return false
	}
	e := l.evaluator.Load()
	return e != nil && e.IsV2ConnectorTool(name)
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
	if tool, registered := verified.V2ConnectorTool(req.Tool, time.Now().UTC()); registered && tool.Route.ConnectorBinding != nil {
		if tool.Route.ConnectorBinding.ConnectorID != req.Connector.ConnectorID {
			return denied("tool_not_registered", "connector tool is not registered for this connector")
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
		capabilityRequired := false
		for _, capability := range tool.RequiredCapabilities {
			if capability == req.Connector.Capability {
				capabilityRequired = true
				break
			}
		}
		if !capabilityFound || !capabilityRequired || len(req.ToolArgs) == 0 {
			return denied("operation_plan_invalid", "credential release requires the complete registered tool arguments and capability")
		}
		contextData := req.ToolContext
		if len(contextData) == 0 {
			contextData = json.RawMessage(`{}`)
		}
		operations, planErr := policybundle.BuildV2Operations(tool, req.Connector.ConnectorID, req.ToolArgs, contextData)
		if planErr != nil {
			return denied("operation_plan_invalid", "tool arguments do not satisfy the registered operation plan")
		}
		resourceMatches := false
		for _, operation := range operations {
			if operation.Capability == req.Connector.Capability && (operation.ProviderResource == req.Resource || operation.CredentialResource == req.Resource) {
				resourceMatches = true
				break
			}
		}
		if !resourceMatches {
			return denied("operation_plan_invalid", "credential resource does not match the registered operation plan")
		}
		d, err := e.AuthorizeV2ConnectorPlan(ctx, pdp.Request{Session: sessionID, Tool: req.Tool, AgentID: trusted}, req.ToolArgs, contextData)
		if err != nil {
			return pdp.Decision{ReasonCode: pdp.ReasonRequestCanceled, DenySource: "runtime_state", Reason: "request canceled", BundleState: "ready"}, true
		}
		return d, true
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
	d, err := e.AuthorizeV2HarnessToolRelease(ctx, pdp.Request{
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
