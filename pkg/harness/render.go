package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/harnessmatch"
)

// ForKind returns the adapter for a supported harness.
func ForKind(kind Kind) (Adapter, error) {
	switch kind {
	case ClaudeCode:
		return ClaudeCodeAdapter{}, nil
	case Codex:
		return CodexAdapter{}, nil
	case OpenCode:
		return OpenCodeAdapter{}, nil
	default:
		return nil, fmt.Errorf("unsupported harness kind %q", kind)
	}
}

// Render is hp-sync's byte-oriented renderer seam.
func Render(kind string, bundle Bundle, cfg []byte) ([]byte, error) {
	k := Kind(kind)
	if _, err := ForKind(k); err != nil {
		return nil, err
	}
	entries, err := CompileEntries(k, bundle, Harness{Kind: k})
	if err != nil {
		return nil, err
	}
	switch k {
	case ClaudeCode:
		var doc map[string]any
		if len(cfg) == 0 {
			cfg = []byte("{}")
		}
		if err = json.Unmarshal(cfg, &doc); err != nil {
			return nil, fmt.Errorf("decode Claude config: %w", err)
		}
		perms, ok := doc["permissions"].(map[string]any)
		if !ok {
			perms = map[string]any{}
			doc["permissions"] = perms
		}
		for _, decision := range []string{"allow", "deny"} {
			key := []string{}
			for _, e := range entries {
				if e.Path == "permissions."+decision {
					key = append(key, e.Value)
				}
			}
			perms[decision] = appendUnique(perms[decision], key)
		}
		return json.MarshalIndent(doc, "", "  ")
	case Codex:
		var rules strings.Builder
		rules.WriteString("# managed by kei harness sync; edits are overwritten\n")
		// Codex has no safe per-command default for `codex exec`; require
		// on-request approval for every command not covered by explicit rules.
		for _, e := range entries {
			if e.Path == "codex.rules" {
				rules.WriteString(e.Value)
				rules.WriteByte('\n')
			}
		}
		return []byte(rules.String()), nil
	case OpenCode:
		var doc map[string]any
		if len(cfg) == 0 {
			cfg = []byte("{}")
		}
		if err = json.Unmarshal(cfg, &doc); err != nil {
			return nil, fmt.Errorf("decode opencode config: %w", err)
		}
		permissions, ok := doc["permission"].(map[string]any)
		if !ok {
			permissions = map[string]any{}
			doc["permission"] = permissions
		}
		bash, ok := permissions["bash"].(map[string]any)
		if !ok {
			bash = map[string]any{}
			permissions["bash"] = bash
		}
		bash["*"] = "ask"
		for _, category := range []string{"skill", "tool"} {
			items, ok := permissions[category].(map[string]any)
			if !ok {
				items = map[string]any{}
				permissions[category] = items
			}
			for _, e := range entries {
				if e.Path == "permission."+category {
					parts := strings.SplitN(e.Value, "=", 2)
					if len(parts) == 2 {
						items[parts[0]] = parts[1]
					}
				}
			}
		}
		for _, e := range entries {
			if e.Path == "permission.bash" {
				bash[e.Value] = decisionKey(e.Decision)
			}
		}
		return json.MarshalIndent(doc, "", "  ")
	}
	return nil, fmt.Errorf("unsupported harness kind %q", kind)
}

func appendUnique(existing any, values []string) []any {
	out := []any{}
	if prior, ok := existing.([]any); ok {
		out = append(out, prior...)
	}
	seen := map[string]bool{}
	for _, v := range out {
		if s, ok := v.(string); ok {
			seen[s] = true
		}
	}
	for _, v := range values {
		if !seen[v] {
			out = append(out, v)
			seen[v] = true
		}
	}
	return out
}

// HookSpec serializes a report-only hook install contract. It contains no
// decision channel; stdout remains empty for Claude Code and Codex.
func HookSpec(kind string, harnessID string) ([]byte, error) {
	if harnessID == "" {
		return nil, errors.New("harness id is required")
	}
	short := map[string]string{"claude_code": "claude", "codex": "codex", "opencode": "opencode"}[kind]
	if short == "" {
		return nil, fmt.Errorf("unsupported harness kind %q", kind)
	}
	spec := struct {
		Schema         string   `json:"schema"`
		Kind           Kind     `json:"kind"`
		Command        []string `json:"command"`
		Phases         []string `json:"phases"`
		TimeoutSeconds int      `json:"timeout_seconds"`
		DecisionOutput bool     `json:"decision_output"`
	}{"kei.harness-hook-spec/v1", Kind(kind), []string{"kei-proxy", "hook", short, "--harness", harnessID}, []string{"pre", "post"}, 5, false}
	return json.Marshal(spec)
}

type compiledPolicy struct {
	ID      string `json:"id"`
	Src     string `json:"src_pattern"`
	Dst     string `json:"dst_pattern"`
	Action  string `json:"action"`
	Enabled bool   `json:"enabled"`
	Scope   struct {
		AgentID string `json:"agent_id"`
	} `json:"scope"`
}
type compiledPolicySet struct {
	Policies []compiledPolicy `json:"policies"`
}

// CompileEntries only compiles closed harness-native selectors. Unsupported or
// ambiguous policy shapes stay unmatched and therefore retain native prompts.
func CompileEntries(kind Kind, bundle VerifiedBundle, h Harness) ([]ManagedEntry, error) {
	if len(bundle.PolicyJSON) == 0 {
		return nil, errors.New("verified bundle has no policy set")
	}
	var set compiledPolicySet
	if err := json.Unmarshal(bundle.PolicyJSON, &set); err != nil {
		return nil, fmt.Errorf("decode policy set: %w", err)
	}
	type candidate struct {
		entry ManagedEntry
		dst   string
	}
	candidates := []candidate{}
	seen := map[string]bool{}
	for i, p := range set.Policies {
		if !p.Enabled || (p.Scope.AgentID != "" && p.Scope.AgentID != h.AgentID) || !sourceApplies(p.Src, h) {
			continue
		}
		if p.Action != string(harnessmatch.OutcomePermit) && p.Action != string(harnessmatch.OutcomeDeny) {
			continue
		}
		path, value, ok := nativeEntry(kind, p.Dst, p.Action)
		if !ok {
			continue
		}
		key := path + "\x00" + value
		if seen[key] {
			continue
		}
		seen[key] = true
		// Human and group sources cannot be resolved by a harness renderer.
		// Their earlier overlapping policy must shadow a later harness permit.
		blocked := false
		if p.Action == string(harnessmatch.OutcomePermit) {
			for _, prior := range set.Policies[:i] {
				if prior.Enabled && (prior.Scope.AgentID == "" || prior.Scope.AgentID == h.AgentID) && unrenderableSource(prior.Src) && destinationsOverlap(prior.Dst, p.Dst) {
					blocked = true
					break
				}
			}
		}
		if blocked {
			continue
		}
		candidates = append(candidates, candidate{entry: ManagedEntry{Path: path, Value: value, Decision: p.Action, PolicyID: p.ID, BundleDigest: bundle.Digest, RemoveOnExpiry: p.Action == string(harnessmatch.OutcomePermit), ExpiresAt: bundle.ExpiresAt}, dst: p.Dst})
		if kind == OpenCode && strings.HasPrefix(p.Dst, "shell:") {
			exact := strings.TrimSpace(strings.TrimPrefix(p.Dst, "shell:"))
			if exact != "" && exact != "*" {
				candidates = append(candidates, candidate{entry: ManagedEntry{Path: "permission.bash", Value: exact, Decision: p.Action, PolicyID: p.ID, BundleDigest: bundle.Digest, RemoveOnExpiry: p.Action == string(harnessmatch.OutcomePermit), ExpiresAt: bundle.ExpiresAt}, dst: p.Dst})
			}
		}
	}
	blocked := make([]bool, len(candidates))
	for i := range candidates {
		for j := i + 1; j < len(candidates); j++ {
			if candidates[i].entry.Decision != candidates[j].entry.Decision && destinationsOverlap(candidates[i].dst, candidates[j].dst) {
				blocked[i] = true
				blocked[j] = true
			}
		}
	}
	out := make([]ManagedEntry, 0, len(candidates))
	for i, c := range candidates {
		if !blocked[i] {
			out = append(out, c.entry)
		}
	}
	return out, nil
}

func unrenderableSource(src string) bool {
	return strings.HasPrefix(src, "user:") || strings.HasPrefix(src, "email:") || strings.HasPrefix(src, "org:") || strings.HasPrefix(src, "group:")
}
func destinationsOverlap(a, b string) bool {
	if a == b || a == "*" || b == "*" || strings.HasPrefix(a, "path:") || strings.HasPrefix(b, "path:") {
		return true
	}
	if strings.HasPrefix(a, "shell:") && strings.HasPrefix(b, "shell:") {
		aa := strings.Fields(strings.TrimPrefix(a, "shell:"))
		bb := strings.Fields(strings.TrimPrefix(b, "shell:"))
		n := len(aa)
		if len(bb) < n {
			n = len(bb)
		}
		if n == 0 {
			return true
		}
		for i := 0; i < n; i++ {
			if aa[i] != bb[i] {
				return false
			}
		}
		return true
	}
	return false
}

// ExpiredEntries returns only Kei-managed allows eligible for removal after
// bundle expiry. Denies remain because they only narrow native permissions.
func ExpiredEntries(entries []ManagedEntry, now time.Time) []ManagedEntry {
	var expired []ManagedEntry
	for _, entry := range entries {
		if entry.RemoveOnExpiry && entry.Decision == string(harnessmatch.OutcomePermit) && !now.Before(entry.ExpiresAt) {
			expired = append(expired, entry)
		}
	}
	return expired
}

func sourceApplies(src string, h Harness) bool {
	applies, _ := harnessmatch.MatchSrc(src, harnessmatch.Call{
		Kind:      string(h.Kind),
		HarnessID: h.ID,
		AgentID:   h.AgentID,
	})
	return applies
}
func nativeEntry(kind Kind, dst, decision string) (string, string, bool) {
	if strings.HasPrefix(dst, "shell:") {
		prefix := strings.TrimSpace(strings.TrimPrefix(dst, "shell:"))
		if prefix == "" || prefix == "*" {
			if decision != string(harnessmatch.OutcomeDeny) {
				return "", "", false
			}
			switch kind {
			case ClaudeCode:
				return "permissions.deny", "Bash(*)", true
			case Codex:
				return "codex.rules", codexRule([]string{"*"}, decision), true
			case OpenCode:
				return "permission.bash", "*", true
			}
		}
		tokens := strings.Fields(prefix)
		if kind == Codex {
			return "codex.rules", codexRule(tokens, decision), true
		}
		if kind == ClaudeCode {
			return "permissions." + decisionKey(decision), "Bash(" + strings.Join(tokens, " ") + ":*)", true
		}
		if kind == OpenCode {
			return "permission.bash", strings.Join(tokens, " ") + " *", true
		}
	}
	for _, scheme := range []string{"tool:", "skill:", "mcp:"} {
		if strings.HasPrefix(dst, scheme) {
			raw := strings.TrimPrefix(dst, scheme)
			if raw == "" || raw == "*" || strings.Contains(raw, "*") {
				return "", "", false
			}
			if scheme == "tool:" && !strings.HasPrefix(raw, string(kind)+".") {
				return "", "", false
			}
			if scheme == "mcp:" && !strings.Contains(raw, ".") {
				return "", "", false
			}
			if strings.HasSuffix(raw, ".bash") || raw == "codex.shell" {
				if decision != string(harnessmatch.OutcomeDeny) {
					return "", "", false
				}
				switch kind {
				case ClaudeCode:
					return "permissions.deny", "Bash(*)", true
				case Codex:
					return "codex.rules", codexRule([]string{"*"}, decision), true
				case OpenCode:
					return "permission.bash", "*", true
				}
			}
			switch kind {
			case ClaudeCode:
				val := raw
				if scheme == "skill:" {
					val = "Skill(" + raw + ")"
				}
				if scheme == "mcp:" {
					val = "mcp__" + strings.ReplaceAll(raw, ".", "__")
				}
				if scheme == "tool:" {
					var ok bool
					val, ok = claudeNativeTool(raw)
					if !ok {
						return "", "", false
					}
				}
				return "permissions." + decisionKey(decision), val, true
			case Codex:
				// Codex prefix_rule controls command argv only; it cannot soundly
				// express native built-in or MCP tool permissions.
				return "", "", false
			case OpenCode:
				if scheme == "skill:" {
					return "permission.skill", raw + "=" + decision, true
				}
				if scheme == "mcp:" {
					raw = "mcp__" + strings.ReplaceAll(raw, ".", "__")
				} else if scheme == "tool:" {
					raw = strings.TrimPrefix(raw, string(kind)+".")
				}
				return "permission.tool", raw + "=" + decision, true
			}
		}
	}
	return "", "", false
}

func claudeNativeTool(name string) (string, bool) {
	for _, tool := range []string{"read", "edit", "write", "bash", "glob", "grep", "task", "webfetch", "web_search", "notebook_edit", "todo_write", "todo_read"} {
		if name == "claude_code."+tool {
			native := strings.ToUpper(tool[:1]) + tool[1:]
			switch tool {
			case "web_search":
				native = "WebSearch"
			case "notebook_edit":
				native = "NotebookEdit"
			case "todo_write":
				native = "TodoWrite"
			case "todo_read":
				native = "TodoRead"
			}
			return native, true
		}
	}
	return "", false
}
func decisionKey(d string) string {
	if d == string(harnessmatch.OutcomePermit) {
		return "allow"
	}
	return "deny"
}
func codexRule(tokens []string, decision string) string {
	q := make([]string, len(tokens))
	for i, t := range tokens {
		q[i] = strconv.Quote(t)
	}
	out := "allow"
	if decision == "deny" {
		out = "forbidden"
	}
	return fmt.Sprintf("prefix_rule(pattern=[%s], decision=%q)", strings.Join(q, ", "), out)
}

func renderPolicy(ctx context.Context, env Env, b VerifiedBundle, h Harness) (RenderPlan, error) {
	if err := ctx.Err(); err != nil {
		return RenderPlan{}, err
	}
	entries, err := CompileEntries(h.Kind, b, h)
	if err != nil {
		return RenderPlan{}, err
	}
	plan := RenderPlan{ExpiresAt: b.ExpiresAt, Managed: entries}
	plan.Hook, err = HookSpec(string(h.Kind), h.ID)
	if err != nil {
		return RenderPlan{}, err
	}
	root := env.HomeDir
	switch h.Kind {
	case ClaudeCode:
		config := env.ConfigDir
		if config == "" {
			config = filepath.Join(root, ".claude")
		}
		plan.ConfigPath = filepath.Join(config, "settings.json")
		plan.Config = readConfig(plan.ConfigPath)
		plan.Config, err = Render(string(h.Kind), b, plan.Config)
		if err != nil {
			return RenderPlan{}, err
		}
	case Codex:
		config := env.ConfigDir
		if config == "" {
			config = filepath.Join(root, ".codex")
		}
		plan.ConfigPath = filepath.Join(config, "rules", "kei.rules")
		plan.Config, err = Render(string(h.Kind), b, nil)
		if err != nil {
			return RenderPlan{}, err
		}
		plan.Managed = append(plan.Managed, ManagedEntry{Path: filepath.Join(config, "config.toml") + ":approval_policy", Value: "on-request", Decision: "baseline", ExpiresAt: b.ExpiresAt})
	case OpenCode:
		config := env.ConfigDir
		if config == "" {
			config = filepath.Join(root, ".config", "opencode")
		}
		plan.ConfigPath = filepath.Join(config, "opencode.json")
		plan.Config = readConfig(plan.ConfigPath)
		plan.Config, err = Render(string(h.Kind), b, plan.Config)
		if err != nil {
			return RenderPlan{}, err
		}
	}
	return plan, nil
}

func readConfig(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		return []byte("{}")
	}
	return b
}

var _ Adapter = ClaudeCodeAdapter{}
var _ Adapter = CodexAdapter{}
var _ Adapter = OpenCodeAdapter{}
var _ Renderer = rendererAdapter{}

type rendererAdapter struct{}

func (rendererAdapter) Render(k string, b Bundle, cfg []byte) ([]byte, error) {
	return Render(k, b, cfg)
}
func (rendererAdapter) HookSpec(k, id string) ([]byte, error) { return HookSpec(k, id) }
func RendererForAdapters() Renderer                           { return rendererAdapter{} }
