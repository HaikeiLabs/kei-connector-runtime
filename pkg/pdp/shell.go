package pdp

import (
	"context"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/shellpolicy"
)

// AuthorizeShell applies v2 shell-prefix policies to a deliberately small
// shell grammar: simple commands joined with && || ; |. Every stage is
// evaluated on its own and the results combine with precedence
// deny > unmatched > allow, so one denied stage denies the whole line and one
// unmatched stage leaves the line unmatched for the caller to defer. Subject
// and membership come only from the live local session and verified bundle;
// agentID must be the daemon's trusted default assignment.
func (e *Evaluator) AuthorizeShell(ctx context.Context, sessionID, command, agentID string) (Decision, error) {
	return e.AuthorizeShellForKind(ctx, sessionID, "pi", command, agentID)
}

// AuthorizeShellForKind is AuthorizeShell for the harness kind whose shell the
// local PDP decides (the bundle registry's shell_tool): harness:<kind>
// policy sources match that kind.
func (e *Evaluator) AuthorizeShellForKind(ctx context.Context, sessionID, kind, command, agentID string) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	if live, reason := e.sessionLive(sessionID); !live {
		return sessionDenial(reason), nil
	}
	if e.sessions == nil {
		return Decision{ReasonCode: ReasonSessionNotFound, DenySource: "identity", Reason: "the session subject is unavailable"}, nil
	}
	current, ok := e.sessions.Get(sessionID)
	if !ok {
		return Decision{ReasonCode: ReasonSessionNotFound, DenySource: "identity", Reason: "the session subject is unavailable"}, nil
	}
	if agentID == "" {
		return Decision{ReasonCode: ReasonAgentNotAssigned, DenySource: "registry", Reason: "the trusted default agent is unavailable"}, nil
	}
	stages, ok := shellpolicy.Parse(command)
	if !ok {
		return Decision{ReasonCode: ReasonUnsupportedShellSyntax, DenySource: "policy", Reason: unsupportedShellReason}, nil
	}
	v, state, err := e.check()
	if err != nil {
		return stateDenial(state), nil
	}
	subject := &policybundle.SessionSubject{
		UserID: current.UserID, Email: current.Email, Source: current.Source,
		ExternalID: current.ExternalID, Status: string(current.Status),
	}
	now := e.now().UTC()
	decision := shellpolicy.Evaluate(stages, func(argv []string) (policybundle.Decision, shellpolicy.Verdict) {
		d := v.EvaluateV2ShellForKind(kind, argv, agentID, subject, now)
		switch {
		case d.Outcome == "allow":
			return d, shellpolicy.Allow
		case d.ReasonCode == "no_matching_policy":
			return d, shellpolicy.Unmatched
		default:
			return d, shellpolicy.Deny
		}
	})
	return Decision{
		Allow: decision.Outcome == "allow", Reason: decision.Reason, ReasonCode: ReasonCode(decision.ReasonCode),
		DenySource: denySource(ReasonCode(decision.ReasonCode)), PolicyID: decision.PolicyID,
		BundleVersion: v.Payload.BundleVersion, BundleDigest: v.Digest,
		PolicyRevision: v.Payload.PolicyRevision, BundleState: string(state),
	}, nil
}

// unsupportedShellReason names what is supported so a denied agent can rewrite
// the command instead of retrying it.
const unsupportedShellReason = "use one command, or commands joined with && || ; |; redirects other than 2>&1 and /dev/null, subshells, substitutions and globs are not supported"

// ShellKindForTool returns the harness kind whose shell command line the local
// PDP decides when tool is that kind's shell tool. The generic "shell" tool is
// always kind pi's. Any other tool is a shell tool only when the verified
// bundle carries a harness kind registry that names it as a kind's shell_tool;
// with no registry, or no bundle yet, the legacy pi.bash is not one.
func (e *Evaluator) ShellKindForTool(tool string) (kind string, ok bool) {
	if tool == "shell" {
		return "pi", true
	}
	v, found := e.Bundle()
	if !found || len(v.Payload.HarnessKinds) == 0 {
		return "", false
	}
	k, ok := v.Payload.HarnessKindForShellTool(tool)
	return k.Kind, ok
}
