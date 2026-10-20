package pdp

import (
	"context"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

// AuthorizePiShell applies v2 shell-prefix policies to one deliberately small
// shell grammar. Subject and membership come only from the live local session
// and verified bundle; agentID must be the daemon's trusted default assignment.
func (e *Evaluator) AuthorizePiShell(ctx context.Context, sessionID, command, agentID string) (Decision, error) {
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
		return Decision{ReasonCode: "agent_not_assigned", DenySource: "registry", Reason: "the trusted default agent is unavailable"}, nil
	}
	argv, ok := parseSimpleShellCommand(command)
	if !ok {
		return Decision{ReasonCode: "unsupported_shell_syntax", DenySource: "policy", Reason: "command is not one supported simple shell command"}, nil
	}
	v, state, err := e.check()
	if err != nil {
		return stateDenial(state), nil
	}
	subject := &policybundle.SessionSubject{
		UserID: current.UserID, Email: current.Email, Source: current.Source,
		ExternalID: current.ExternalID, Groups: current.Groups, Status: string(current.Status),
	}
	decision := v.EvaluateV2PiShell(argv, agentID, subject, e.now().UTC())
	return Decision{
		Allow: decision.Outcome == "allow", Reason: decision.Reason, ReasonCode: decision.ReasonCode,
		DenySource: denySource(decision.ReasonCode), PolicyID: decision.PolicyID,
		BundleVersion: v.Payload.BundleVersion, BundleDigest: v.Digest,
		PolicyRevision: v.Payload.PolicyRevision, BundleState: string(state),
	}, nil
}

// parseSimpleShellCommand tokenizes words with single/double quotes and
// backslash escapes. It rejects substitutions, expansions, operators,
// redirections, globs, and control characters instead of guessing shell
// semantics. It is not a general shell parser.
func parseSimpleShellCommand(command string) ([]string, bool) {
	if command == "" || !utf8.ValidString(command) {
		return nil, false
	}
	var argv []string
	var word strings.Builder
	var quote rune
	started := false
	escaped := false
	for _, r := range command {
		if unicode.IsControl(r) {
			return nil, false
		}
		if escaped {
			if r == '\n' || r == '\r' {
				return nil, false
			}
			word.WriteRune(r)
			started, escaped = true, false
			continue
		}
		if quote == '\'' {
			if r == '\'' {
				quote = 0
			} else {
				word.WriteRune(r)
			}
			started = true
			continue
		}
		if quote == '"' {
			switch r {
			case '"':
				quote = 0
			case '$', '`', '\\':
				return nil, false
			default:
				word.WriteRune(r)
			}
			started = true
			continue
		}
		if r == '\'' || r == '"' {
			quote, started = r, true
			continue
		}
		if r == '\\' {
			escaped, started = true, true
			continue
		}
		if r == ' ' || r == '\t' {
			if started {
				argv = append(argv, word.String())
				word.Reset()
				started = false
			}
			continue
		}
		if strings.ContainsRune(";&|<>$`(){}*?[]~!#", r) {
			return nil, false
		}
		word.WriteRune(r)
		started = true
	}
	if quote != 0 || escaped {
		return nil, false
	}
	if started {
		argv = append(argv, word.String())
	}
	return argv, len(argv) > 0
}
