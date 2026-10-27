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
	// Deny means the stage is refused, by a policy or any other reason.
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

// Parse tokenizes a command into stages split on unquoted && || ; |.
// Words follow shell quoting: single quotes are literal, double quotes reject
// $ ` and backslash, a backslash escapes one character. The only redirects
// accepted (and dropped from argv) are 2>&1 and >, 1>, 2> to /dev/null.
// Everything else (expansions, other redirects, subshells, background, globs,
// ~ ! #, control characters, empty stages, over-long input) rejects the whole
// line rather than guess shell semantics. It is not a general shell parser.
func Parse(command string) ([][]string, bool) {
	if command == "" || len(command) > MaxCommandBytes || !utf8.ValidString(command) {
		return nil, false
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
			return nil, false
		}
		switch r {
		case '\\':
			i++
			if i == len(runes) || unicode.IsControl(runes[i]) {
				return nil, false
			}
			word.WriteRune(runes[i])
			started, literal = true, true
		case '\'':
			started, literal = true, true
			for i++; i < len(runes) && runes[i] != '\''; i++ {
				if unicode.IsControl(runes[i]) {
					return nil, false
				}
				word.WriteRune(runes[i])
			}
			if i == len(runes) {
				return nil, false
			}
		case '"':
			started, literal = true, true
			for i++; i < len(runes) && runes[i] != '"'; i++ {
				if unicode.IsControl(runes[i]) || strings.ContainsRune("$`\\", runes[i]) {
					return nil, false
				}
				word.WriteRune(runes[i])
			}
			if i == len(runes) {
				return nil, false
			}
		case ' ':
			flushWord()
		case ';':
			if !endStage() {
				return nil, false
			}
		case '|':
			if i+1 < len(runes) && runes[i+1] == '|' {
				i++
			}
			if !endStage() {
				return nil, false
			}
		case '&':
			// Only && joins stages; a lone & backgrounds, &> redirects.
			if i+1 >= len(runes) || runes[i+1] != '&' {
				return nil, false
			}
			i++
			if !endStage() {
				return nil, false
			}
		case '>':
			fd := word.String()
			if started && (literal || (fd != "1" && fd != "2")) {
				return nil, false
			}
			j := i + 1
			if j < len(runes) && runes[j] == '&' {
				// Only 2>&1.
				if fd != "2" || j+1 >= len(runes) || runes[j+1] != '1' || !boundary(j+2) {
					return nil, false
				}
				i = j + 1
			} else {
				for j < len(runes) && runes[j] == ' ' {
					j++
				}
				const devNull = "/dev/null"
				end := j + len(devNull)
				if end > len(runes) || string(runes[j:end]) != devNull || !boundary(end) {
					return nil, false
				}
				i = end - 1
			}
			word.Reset()
			started, literal = false, false
		case '<', '$', '`', '(', ')', '{', '}', '*', '?', '[', ']', '~', '!', '#':
			return nil, false
		default:
			word.WriteRune(r)
			started = true
		}
	}
	if !endStage() {
		return nil, false
	}
	return stages, true
}
