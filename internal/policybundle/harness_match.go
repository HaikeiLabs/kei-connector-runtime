package policybundle

import (
	"path"
	"strings"
)

// Harness kinds named by harness: sources (ADR-029 §1.3).
var harnessKinds = map[string]bool{"claude_code": true, "codex": true, "opencode": true}

// HarnessCall is one tool call of a pre-built harness, described by the
// inputs kei.harness-match/v1 matches on (ADR-029 §1.2, §1.3).
type HarnessCall struct {
	HarnessID string   // registered harness id (UUID)
	Kind      string   // claude_code | codex | opencode
	AgentID   string   // agent the harness runs as, if any
	Tool      string   // registry tool name, e.g. claude_code.edit
	Argv      []string // shell commands only
	Skill     string   // skill invocations only
	Path      string   // absolute path outside the working directory
	Home      string   // home directory that a leading ~/ in path: globs expands to
	MCPServer string
	MCPTool   string
}

// Harness outcomes (ADR-029 §1.5). There are no reason codes on this path.
const (
	HarnessPermit        = policyPermitAction
	HarnessDeny          = "deny"
	HarnessUnmatched     = "unmatched"
	HarnessNotRenderable = "not_renderable"
)

// EvaluateHarness gives the kei.harness-match/v1 outcome of a harness tool
// call: the first policy, in catalog order, whose source applies to the
// harness and whose destination matches the call. A human source gives
// not_renderable. For a shell command a permit counts only when its dst is a
// shell: argv prefix (ADR-029 §9.4). Renderers use this outcome; kei-proxy
// does not enforce it at run time.
func (v *Verified) EvaluateHarness(c HarnessCall) (outcome, policyID string) {
	if !harnessKinds[c.Kind] {
		return HarnessNotRenderable, ""
	}
	if c.Path != "" && (!path.IsAbs(c.Path) || path.Clean(c.Path) != c.Path) {
		return HarnessNotRenderable, ""
	}
	set, err := v.decodePolicySet()
	if err != nil {
		return HarnessNotRenderable, ""
	}
	shell := len(c.Argv) > 0
	for _, p := range set.Policies {
		if p.Scope.AgentID != nil && *p.Scope.AgentID != c.AgentID {
			continue
		}
		matched, renderable := harnessDstMatch(p.Dst, c)
		if !matched {
			continue
		}
		if shell && p.Action == policyPermitAction && (!strings.HasPrefix(p.Dst, "shell:") || p.Dst == "shell:*") {
			continue
		}
		applies, human := harnessSrcApplies(p.Src, c)
		if !applies && !human {
			continue
		}
		if human || !renderable {
			return HarnessNotRenderable, p.ID
		}
		if p.Action == "deny" {
			return HarnessDeny, p.ID
		}
		if p.Action == policyPermitAction {
			return HarnessPermit, p.ID
		}
	}
	return HarnessUnmatched, ""
}

func harnessSrcApplies(src string, c HarnessCall) (applies, human bool) {
	switch {
	case src == "*", src == "harness:*":
		return true, false
	case strings.HasPrefix(src, "harness:"):
		v := strings.TrimPrefix(src, "harness:")
		return v == c.Kind || (c.HarnessID != "" && v == c.HarnessID), false
	case strings.HasPrefix(src, "agent:"):
		v := strings.TrimPrefix(src, "agent:")
		return c.AgentID != "" && (v == "*" || v == c.AgentID), false
	}
	return false, true
}

// harnessDstMatch reports whether dst matches the call. renderable is false
// when the pattern cannot be evaluated for this call (a ~/ glob with no home).
func harnessDstMatch(dst string, c HarnessCall) (matched, renderable bool) {
	if dst == "*" {
		return true, true
	}
	scheme, value, ok := strings.Cut(dst, ":")
	if !ok {
		return false, true
	}
	switch scheme {
	case "shell":
		if len(c.Argv) == 0 {
			return false, true
		}
		if value == "*" {
			return true, true
		}
		tokens := strings.Split(value, " ")
		if len(tokens) > len(c.Argv) {
			return false, true
		}
		for i, t := range tokens {
			if t == "" || t != c.Argv[i] {
				return false, true
			}
		}
		return true, true
	case "skill":
		return c.Skill != "" && (value == "*" || value == c.Skill), true
	case "path":
		if c.Path == "" {
			return false, true
		}
		if value == "*" {
			return true, true
		}
		if strings.HasPrefix(value, "~/") {
			if c.Home == "" {
				return true, false
			}
			value = strings.TrimSuffix(c.Home, "/") + value[1:]
		}
		return globMatch(strings.Split(value, "/"), strings.Split(c.Path, "/")), true
	case "mcp":
		if c.MCPServer == "" {
			return false, true
		}
		return value == "*" || value == c.MCPServer || (c.MCPTool != "" && value == c.MCPServer+"."+c.MCPTool), true
	case "tool":
		return c.Tool != "" && (value == "*" || value == c.Tool), true
	}
	return false, true
}

// globMatch matches path segments: ** as a whole segment matches zero or more
// segments, * matches any characters within one segment, nothing else is special.
func globMatch(pattern, segs []string) bool {
	if len(pattern) == 0 {
		return len(segs) == 0
	}
	if pattern[0] == "**" {
		for i := 0; i <= len(segs); i++ {
			if globMatch(pattern[1:], segs[i:]) {
				return true
			}
		}
		return false
	}
	if len(segs) == 0 || !segmentMatch(pattern[0], segs[0]) {
		return false
	}
	return globMatch(pattern[1:], segs[1:])
}

func segmentMatch(pattern, seg string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == seg
	}
	if !strings.HasPrefix(seg, parts[0]) {
		return false
	}
	seg = seg[len(parts[0]):]
	for _, part := range parts[1 : len(parts)-1] {
		i := strings.Index(seg, part)
		if i < 0 {
			return false
		}
		seg = seg[i+len(part):]
	}
	return strings.HasSuffix(seg, parts[len(parts)-1])
}
