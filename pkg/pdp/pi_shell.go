package pdp

import (
	"context"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

// AuthorizePiShell applies harness shell-prefix policies to one deliberately
// small shell grammar. Unsupported shell syntax fails closed.
func (e *Evaluator) AuthorizePiShell(ctx context.Context, command, agentID string) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	argv, ok := parseSimpleShellCommand(command)
	if !ok {
		return Decision{ReasonCode: "unsupported_shell_syntax", DenySource: "policy", Reason: "command is not one supported simple shell command"}, nil
	}
	result, err := e.EvaluateHarness(ctx, HarnessCall{Kind: "pi", AgentID: agentID, Argv: argv})
	if err != nil {
		return Decision{}, err
	}
	d := Decision{PolicyID: result.PolicyID, ReasonCode: result.Reason, DenySource: "policy"}
	switch result.Outcome {
	case policybundle.HarnessPermit:
		d.Allow = true
	case policybundle.HarnessDeny:
		d.ReasonCode = "policy_deny"
	case policybundle.HarnessUnmatched:
		d.ReasonCode = "policy_unmatched"
		d.Reason = "no matching shell policy"
	default:
		d.ReasonCode = "shell_policy_unavailable"
		d.Reason = "shell policy could not be evaluated"
		d.DenySource = "runtime_state"
	}
	return d, nil
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
