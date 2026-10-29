package pdp

import "context"

// Target is what a call acts on. Adapters (the socket handler, the shell
// parser) turn a wire request into one: Shell for a shell command, Connector
// for a connector capability, otherwise Tool by registry name.
type Target struct {
	Tool      string
	Action    string // optional; must equal the registered action
	Resource  string
	Connector *ConnectorTarget
	Shell     string // a command line; makes this a shell target
	// ShellKind is the harness kind whose shell this is; empty means pi.
	ShellKind string
}

// DecideRequest is one governed call for Decide. The subject is the session's;
// it is never taken from the caller.
type DecideRequest struct {
	Session string
	Target  Target
	// AgentID is the agent the caller named. It is untrusted: Decide denies a
	// call that names an agent other than TrustedAgent.
	AgentID string
	// TrustedAgent is the authenticated runtime identity's default agent.
	TrustedAgent string
	// OwnerSession is true when Session is the verified installation-owner
	// session, which alone may use unregistered tool names.
	OwnerSession bool
}

// DecideResult is Decide's outcome. Unmatched marks a deny that only means no
// policy covered the call, so a harness may defer to its native handling.
// AuditTrustedAgent is true when the decision used TrustedAgent, so the audit
// should record that agent instead of the caller's.
type DecideResult struct {
	Decision
	Unmatched         bool
	AuditTrustedAgent bool
}

// Decide is the one entry point for a governed call. It routes the target to
// the shell, unregistered-tool, harness-tool or registered-tool decision.
// The error is non-nil only when ctx is done.
func (e *Evaluator) Decide(ctx context.Context, req DecideRequest) (DecideResult, error) {
	t := req.Target
	preq := Request{Session: req.Session, Tool: t.Tool, Action: t.Action, Resource: t.Resource, AgentID: req.AgentID, Connector: t.Connector}
	if t.Shell != "" {
		kind := t.ShellKind
		if kind == "" {
			kind = "pi"
		}
		d, err := e.AuthorizeShellForKind(ctx, req.Session, kind, t.Shell, req.TrustedAgent)
		return DecideResult{Decision: d, Unmatched: d.ReasonCode == ReasonNoMatchingPolicy, AuditTrustedAgent: true}, err
	}
	switch {
	case t.Tool != "" && t.Connector == nil && req.OwnerSession && e.IsV2UnregisteredTool(t.Tool):
		// Unregistered tool names receive a local policy decision by name.
		// Identity and memberships come from the verified installation-owner
		// session, never the request.
		return e.decideAsTrustedAgent(ctx, req, preq, e.AuthorizeV2UnregisteredTool, true)
	case e.IsV2HarnessTool(t.Tool):
		return e.decideAsTrustedAgent(ctx, req, preq, e.AuthorizeV2HarnessTool, false)
	}
	// For v2 bundles, resolve the agent from the runtime identity. For v1
	// bundles, Evaluate resolves it from the bundle default.
	if v, ok := e.Bundle(); ok && v.Payload.Schema == "kei.policy-bundle/v2" {
		res, err := e.decideAsTrustedAgent(ctx, req, preq, e.Evaluate, false)
		if err == nil {
			res.Decision = e.explainPreflight(t.Tool, res.Decision)
		}
		return res, err
	}
	d, err := e.Evaluate(ctx, preq)
	if err == nil {
		d = e.explainPreflight(t.Tool, d)
	}
	return DecideResult{Decision: d}, err
}

// explainPreflight says why a registered-tool call that the bundle sends to
// preflight cannot be authorized here: a connector_binding tool needs the
// complete-plan preflight, and any other route means the tool is not
// registered for a harness executor.
func (e *Evaluator) explainPreflight(tool string, d Decision) Decision {
	if d.ReasonCode != ReasonPreflightRequired {
		return d
	}
	route, isV2 := e.V2ToolRoute(tool)
	if !isV2 {
		return d
	}
	switch route {
	case "connector_binding":
		d.Reason = "tool is registered with a connector_binding route; complete-plan preflight is required, so /v1/authorize cannot authorize it"
	default:
		d.ReasonCode = ReasonToolNotRegistered
		d.DenySource = "registry"
		d.Reason = "tool is not registered with a harness_executor route in the active v2 policy bundle; re-sync the harness tool manifest"
	}
	return d
}

// decideAsTrustedAgent decides for the authenticated runtime identity's
// default agent, and denies a request that names any other agent.
func (e *Evaluator) decideAsTrustedAgent(ctx context.Context, req DecideRequest, preq Request, decide func(context.Context, Request) (Decision, error), flagUnmatched bool) (DecideResult, error) {
	if req.TrustedAgent == "" {
		return DecideResult{Decision: Decision{ReasonCode: ReasonAgentNotAssigned, DenySource: "registry", Reason: "the trusted default agent is unavailable"}, AuditTrustedAgent: true}, nil
	}
	if req.AgentID != "" && req.AgentID != req.TrustedAgent {
		return DecideResult{Decision: Decision{ReasonCode: ReasonAgentMismatch, DenySource: "registry", Reason: "the request agent is not this installation's default agent"}, AuditTrustedAgent: true}, nil
	}
	preq.AgentID = req.TrustedAgent
	d, err := decide(ctx, preq)
	return DecideResult{Decision: d, Unmatched: flagUnmatched && d.ReasonCode == ReasonNoMatchingPolicy, AuditTrustedAgent: true}, err
}
