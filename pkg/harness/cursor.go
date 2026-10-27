package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/HaikeiLabs/kei-connector-contracts/harnessmatch"
)

// CursorAdapter discovers Cursor CLI built-ins, MCP servers and installed
// skills, and renders Kei policy into the Cursor CLI permission arrays in
// ~/.cursor/cli-config.json. Policies the native permission tokens cannot
// express (skill rules, multi-token shell argv rules) stay out of the config
// and are reported as plan warnings so kei connect can surface them.
type CursorAdapter struct{}

func (CursorAdapter) Kind() Kind { return Cursor }

func (CursorAdapter) DiscoverTools(ctx context.Context, env Env) (Discovery, error) {
	if err := ctx.Err(); err != nil {
		return Discovery{}, err
	}
	root := env.HomeDir
	if root == "" {
		root, _ = os.UserHomeDir()
	}
	if root == "" {
		return Discovery{}, errors.New("home directory is required")
	}
	config := env.ConfigDir
	if config == "" {
		config = filepath.Join(root, ".cursor")
	}
	builtins, err := builtinsForKind(Cursor)
	if err != nil {
		return Discovery{}, err
	}
	d := Discovery{BuiltIns: builtins}
	var warnings []string
	configs := []string{filepath.Join(config, "mcp.json")}
	if env.ProjectDir != "" {
		configs = append(configs, filepath.Join(env.ProjectDir, ".cursor", "mcp.json"))
	}
	for _, mcpPath := range configs {
		data, err := os.ReadFile(mcpPath)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return Discovery{}, fmt.Errorf("read Cursor MCP config: %w", err)
		}
		var mcp struct {
			MCPServers map[string]struct {
				Disabled bool `json:"disabled"`
			} `json:"mcpServers"`
		}
		if err = json.Unmarshal(data, &mcp); err != nil {
			warnings = append(warnings, "invalid Cursor MCP config")
			continue
		}
		servers := make([]string, 0, len(mcp.MCPServers))
		for server := range mcp.MCPServers {
			servers = append(servers, server)
		}
		sort.Strings(servers)
		for _, server := range servers {
			if mcp.MCPServers[server].Disabled {
				continue
			}
			name, e := registryName(Cursor, "mcp", server)
			if e != nil {
				warnings = append(warnings, e.Error())
				continue
			}
			d.MCP = append(d.MCP, Tool{Name: name, Service: "harness", Source: "mcp", Selector: "mcp:" + server, Executor: "cursor", Registration: "mcp:" + server, OperationClass: "write", Description: "MCP server " + server})
		}
	}
	skillDirs := []string{filepath.Join(config, "skills"), filepath.Join(root, ".agents", "skills")}
	if env.ProjectDir != "" {
		skillDirs = append(skillDirs, filepath.Join(env.ProjectDir, ".cursor", "skills"), filepath.Join(env.ProjectDir, ".agents", "skills"))
	}
	for _, dir := range skillDirs {
		if err := discoverSkills(ctx, dir, Cursor, &d, &warnings); err != nil {
			return Discovery{}, err
		}
	}
	if len(warnings) > 0 {
		d.Warnings = warnings
	}
	filterDuplicateNames(&d)
	return d, nil
}

func (CursorAdapter) RenderPolicy(ctx context.Context, env Env, b VerifiedBundle, h Harness) (RenderPlan, error) {
	h.Kind = Cursor
	plan, err := renderPolicy(ctx, env, b, h)
	if err != nil {
		return RenderPlan{}, err
	}
	plan.Warnings = append(plan.Warnings, cursorUngateableWarnings(b, h)...)
	return plan, nil
}

func (CursorAdapter) Hook(ctx context.Context, rec Recorder, h Harness, stdin io.Reader, stdout io.Writer) error {
	return reportHook(ctx, rec, h, stdin, stdout)
}

// cursorUngateableWarnings reports the enabled permit/deny policies for this
// harness whose destination the native permission tokens cannot express, so
// kei connect can print them as hook-only or ungateable instead of silently
// dropping them.
func cursorUngateableWarnings(b VerifiedBundle, h Harness) []string {
	if len(b.PolicyJSON) == 0 {
		return nil
	}
	var set compiledPolicySet
	if err := json.Unmarshal(b.PolicyJSON, &set); err != nil {
		return nil
	}
	var warnings []string
	for _, p := range set.Policies {
		if !p.Enabled || (p.Scope.AgentID != "" && p.Scope.AgentID != h.AgentID) || !sourceApplies(p.Src, h) {
			continue
		}
		if p.Action != string(harnessmatch.OutcomePermit) && p.Action != string(harnessmatch.OutcomeDeny) {
			continue
		}
		if _, _, ok := nativeEntry(Cursor, p.Dst, p.Action); !ok {
			warnings = append(warnings, fmt.Sprintf("policy %s: %q is not gateable by cursor native permissions; it stays with the kei PDP and native prompts", p.ID, p.Dst))
		}
	}
	return warnings
}

// cursorShellEntry maps a shell argv prefix to the native Shell(base) token.
// Cursor permissions match one base command token, so only single-token argv
// prefixes compile; multi-token rules stay with the kei PDP.
func cursorShellEntry(tokens []string, decision string) (string, string, bool) {
	if len(tokens) != 1 {
		return "", "", false
	}
	return "permissions." + decisionKey(decision), "Shell(" + tokens[0] + ":*)", true
}

// cursorToolEntry maps tool:cursor.* and mcp:server.tool destinations to the
// native Read/Write/WebFetch and Mcp tokens.
func cursorToolEntry(scheme, raw, decision string) (string, string, bool) {
	key := "permissions." + decisionKey(decision)
	if scheme == "mcp:" {
		server, tool, _ := strings.Cut(raw, ".")
		return key, "Mcp(" + server + ":" + tool + ")", true
	}
	raw = strings.TrimPrefix(raw, string(Cursor)+".")
	switch raw {
	case "read":
		return key, "Read(**)", true
	case "write", "edit":
		return key, "Write(**)", true
	case "webfetch":
		return key, "WebFetch(*)", true
	}
	return "", "", false
}
