// Package shellpolicy parses a small, deliberately strict shell grammar and
// combines per-stage policy verdicts for it. It knows nothing about any policy
// engine: callers supply the per-stage evaluation.
package shellpolicy

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits on the grammar Parse accepts.
const (
	MaxCommandBytes = 4096
	MaxStages       = 16
)

// Verdict is one stage's policy outcome.
type Verdict int

const (
	// Allow means a policy explicitly permits the stage.
	Allow Verdict = iota
	// Unmatched means no policy applies to the stage.
	Unmatched
	// Deny means a policy refuses the stage.
	Deny
)

// Evaluate runs eval on each stage and combines the results with precedence
// Deny > Unmatched > Allow. It returns the decision of the first denying stage
// (stopping there), else of the first unmatched stage, else of the first
// stage. stages must be non-empty, as Parse guarantees.
func Evaluate[D any](stages [][]string, eval func(argv []string) (D, Verdict)) D {
	var first, unmatched D
	haveFirst, haveUnmatched := false, false
	for _, argv := range stages {
		d, v := eval(argv)
		switch v {
		case Allow:
		case Unmatched:
			if !haveUnmatched {
				unmatched, haveUnmatched = d, true
			}
		default:
			return d
		}
		if !haveFirst {
			first, haveFirst = d, true
		}
	}
	if haveUnmatched {
		return unmatched
	}
	return first
}

// DiagnosticCode is a bounded, stable category for why Parse rejected input.
// It deliberately contains neither command text nor offsets into the command.
type DiagnosticCode string

const (
	DiagnosticInvalidInput                DiagnosticCode = "invalid_input"
	DiagnosticInputTooLarge               DiagnosticCode = "input_too_large"
	DiagnosticControlCharacter            DiagnosticCode = "control_character"
	DiagnosticMalformedQuoting            DiagnosticCode = "malformed_quoting"
	DiagnosticParameterExpansion          DiagnosticCode = "parameter_expansion"
	DiagnosticCommandSubstitution         DiagnosticCode = "command_substitution"
	DiagnosticBacktickSubstitution        DiagnosticCode = "backtick_substitution"
	DiagnosticUnsupportedRedirection      DiagnosticCode = "unsupported_redirection"
	DiagnosticUnsupportedGrouping         DiagnosticCode = "unsupported_grouping"
	DiagnosticUnsupportedGlob             DiagnosticCode = "unsupported_glob"
	DiagnosticUnsupportedBackground       DiagnosticCode = "unsupported_background"
	DiagnosticUnsupportedTildeExpansion   DiagnosticCode = "tilde_expansion"
	DiagnosticUnsupportedHistoryExpansion DiagnosticCode = "history_expansion"
	DiagnosticUnsupportedShellComment     DiagnosticCode = "shell_comment"
	DiagnosticInvalidCommandStructure     DiagnosticCode = "invalid_command_structure"
)

// Parse tokenizes a command into stages split on unquoted && || ; |.
// Words follow shell quoting: single quotes are literal, double quotes reject
// $ ` and backslash, a backslash escapes one character. The only redirects
// accepted (and dropped from argv) are 2>&1 and >, 1>, 2> to /dev/null.
// Everything else rejects the whole line rather than guess shell semantics.
// It is not a general shell parser.
func Parse(command string) ([][]string, bool) {
	stages, diagnostic := ParseWithDiagnostic(command)
	return stages, diagnostic == ""
}

// ParseWithDiagnostic is Parse with a bounded category for rejected input.
// Success returns an empty diagnostic. The parser never returns input text.
func ParseWithDiagnostic(command string) ([][]string, DiagnosticCode) {
	if command == "" || !utf8.ValidString(command) {
		return nil, DiagnosticInvalidInput
	}
	if len(command) > MaxCommandBytes {
		return nil, DiagnosticInputTooLarge
	}
	runes := []rune(command)
	var (
		stages  [][]string
		argv    []string
		word    strings.Builder
		started bool // a word is open, possibly empty (e.g. "")
		literal bool // the open word held a quote or escape, so it is never a redirect fd
	)
	flushWord := func() {
		if started {
			argv = append(argv, word.String())
			word.Reset()
			started, literal = false, false
		}
	}
	endStage := func() bool {
		flushWord()
		if len(argv) == 0 || len(stages) == MaxStages {
			return false
		}
		stages = append(stages, argv)
		argv = nil
		return true
	}
	// boundary reports whether a redirect may end before runes[j].
	boundary := func(j int) bool {
		return j >= len(runes) || strings.ContainsRune(" ;&|", runes[j])
	}
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if unicode.IsControl(r) {
			return nil, DiagnosticControlCharacter
		}
		switch r {
		case '\\':
			i++
			if i == len(runes) {
				return nil, DiagnosticMalformedQuoting
			}
			if unicode.IsControl(runes[i]) {
				return nil, DiagnosticControlCharacter
			}
			word.WriteRune(runes[i])
			started, literal = true, true
		case '\'':
			started, literal = true, true
			for i++; i < len(runes) && runes[i] != '\''; i++ {
				if unicode.IsControl(runes[i]) {
					return nil, DiagnosticControlCharacter
				}
				word.WriteRune(runes[i])
			}
			if i == len(runes) {
				return nil, DiagnosticMalformedQuoting
			}
		case '"':
			started, literal = true, true
			for i++; i < len(runes) && runes[i] != '"'; i++ {
				if unicode.IsControl(runes[i]) {
					return nil, DiagnosticControlCharacter
				}
				if runes[i] == '$' || runes[i] == '`' {
					return nil, expansionDiagnostic(runes, i)
				}
				if runes[i] == '\\' {
					return nil, DiagnosticMalformedQuoting
				}
				word.WriteRune(runes[i])
			}
			if i == len(runes) {
				return nil, DiagnosticMalformedQuoting
			}
		case ' ':
			flushWord()
		case ';':
			if !endStage() {
				return nil, DiagnosticInvalidCommandStructure
			}
		case '|':
			if i+1 < len(runes) && runes[i+1] == '|' {
				i++
			}
			if !endStage() {
				return nil, DiagnosticInvalidCommandStructure
			}
		case '&':
			// Only && joins stages; a lone & backgrounds, &> redirects.
			if i+1 >= len(runes) || runes[i+1] != '&' {
				if i+1 < len(runes) && runes[i+1] == '>' {
					return nil, DiagnosticUnsupportedRedirection
				}
				return nil, DiagnosticUnsupportedBackground
			}
			i++
			if !endStage() {
				return nil, DiagnosticInvalidCommandStructure
			}
		case '>':
			fd := word.String()
			if started && (literal || (fd != "1" && fd != "2")) {
				return nil, DiagnosticUnsupportedRedirection
			}
			j := i + 1
			if j < len(runes) && runes[j] == '&' {
				// Only 2>&1.
				if fd != "2" || j+1 >= len(runes) || runes[j+1] != '1' || !boundary(j+2) {
					return nil, DiagnosticUnsupportedRedirection
				}
				i = j + 1
			} else {
				for j < len(runes) && runes[j] == ' ' {
					j++
				}
				const devNull = "/dev/null"
				end := j + len(devNull)
				if end > len(runes) || string(runes[j:end]) != devNull || !boundary(end) {
					return nil, DiagnosticUnsupportedRedirection
				}
				i = end - 1
			}
			word.Reset()
			started, literal = false, false
		case '<':
			return nil, DiagnosticUnsupportedRedirection
		case '$', '`':
			return nil, expansionDiagnostic(runes, i)
		case '(', ')', '{', '}':
			return nil, DiagnosticUnsupportedGrouping
		case '*', '?', '[', ']':
			return nil, DiagnosticUnsupportedGlob
		case '~':
			return nil, DiagnosticUnsupportedTildeExpansion
		case '!':
			return nil, DiagnosticUnsupportedHistoryExpansion
		case '#':
			return nil, DiagnosticUnsupportedShellComment
		default:
			word.WriteRune(r)
			started = true
		}
	}
	if !endStage() {
		return nil, DiagnosticInvalidCommandStructure
	}
	return stages, ""
}

func expansionDiagnostic(runes []rune, i int) DiagnosticCode {
	if runes[i] == '`' {
		return DiagnosticBacktickSubstitution
	}
	if i+1 < len(runes) && runes[i+1] == '(' {
		return DiagnosticCommandSubstitution
	}
	return DiagnosticParameterExpansion
}
