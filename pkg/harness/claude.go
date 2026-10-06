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
)

// ClaudeCodeAdapter discovers Claude Code built-ins and installed extensions.
type ClaudeCodeAdapter struct{}

func (ClaudeCodeAdapter) Kind() Kind { return ClaudeCode }

func (ClaudeCodeAdapter) DiscoverTools(ctx context.Context, env Env) (Discovery, error) {
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
		config = filepath.Join(root, ".claude")
	}
	builtins, err := builtinsForKind(ClaudeCode)
	if err != nil {
		return Discovery{}, err
	}
	d := Discovery{BuiltIns: builtins}
	var warnings []string
	configs := []string{filepath.Join(config, "settings.json"), filepath.Join(config, "settings.local.json")}
	if env.ProjectDir != "" {
		configs = append(configs, filepath.Join(env.ProjectDir, ".mcp.json"))
	}
	for _, settingsPath := range configs {
		data, err := os.ReadFile(settingsPath)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return Discovery{}, fmt.Errorf("read Claude config: %w", err)
		}
		var settings struct {
			MCPServers map[string]struct {
				Disabled bool `json:"disabled"`
				Tools    []struct {
					Name        string `json:"name"`
					Description string `json:"description"`
					ReadOnly    bool   `json:"readOnly"`
				} `json:"tools"`
			} `json:"mcpServers"`
		}
		if err = json.Unmarshal(data, &settings); err != nil {
			warnings = append(warnings, "invalid Claude MCP config")
			continue
		}
		servers := make([]string, 0, len(settings.MCPServers))
		for server := range settings.MCPServers {
			servers = append(servers, server)
		}
		sort.Strings(servers)
		for _, server := range servers {
			cfg := settings.MCPServers[server]
			if cfg.Disabled {
				continue
			}
			if len(cfg.Tools) == 0 {
				name, e := registryName(ClaudeCode, "mcp", server)
				if e != nil {
					warnings = append(warnings, e.Error())
					continue
				}
				d.MCP = append(d.MCP, Tool{Name: name, Service: "harness", Source: "mcp", Selector: "mcp:" + server, Executor: "claude_code", Registration: "mcp:" + server, OperationClass: "write", Description: "MCP server " + server})
				continue
			}
			for _, mt := range cfg.Tools {
				name, e := registryName(ClaudeCode, "mcp", server, mt.Name)
				if e != nil {
					warnings = append(warnings, e.Error())
					continue
				}
				class := "write"
				if mt.ReadOnly {
					class = "read"
				}
				d.MCP = append(d.MCP, Tool{Name: name, Service: "harness", Source: "mcp", Selector: "mcp:" + server + "." + mt.Name, Executor: "claude_code", Registration: "mcp:" + server + "." + mt.Name, OperationClass: class, Description: mt.Description})
			}
		}
	}
	skillDirs := []string{filepath.Join(config, "skills"), filepath.Join(root, ".agents", "skills")}
	if env.ProjectDir != "" {
		skillDirs = append(skillDirs, filepath.Join(env.ProjectDir, ".claude", "skills"))
	}
	for _, dir := range skillDirs {
		if err := discoverSkills(ctx, dir, ClaudeCode, &d, &warnings); err != nil {
			return Discovery{}, err
		}
	}
	if len(warnings) > 0 {
		d.Warnings = warnings
	}
	filterDuplicateNames(&d)
	return d, nil
}

func (ClaudeCodeAdapter) RenderPolicy(ctx context.Context, env Env, b VerifiedBundle, h Harness) (RenderPlan, error) {
	h.Kind = ClaudeCode
	return renderPolicy(ctx, env, b, h)
}

func (ClaudeCodeAdapter) Hook(ctx context.Context, rec Recorder, h Harness, stdin io.Reader, stdout io.Writer) error {
	return reportHook(ctx, rec, h, stdin, stdout)
}

func discoverSkills(ctx context.Context, dir string, kind Kind, d *Discovery, warnings *[]string) error {
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		if entry.IsDir() || entry.Name() != "SKILL.md" {
			return nil
		}
		name := filepath.Base(filepath.Dir(path))
		description := "Installed skill " + name
		b, e := os.ReadFile(path)
		if e != nil {
			*warnings = append(*warnings, "unreadable skill file")
			return nil
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "name:") {
				name = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "name:")), "\"'")
			}
			if strings.HasPrefix(line, "description:") {
				description = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "description:")), "\"'")
			}
		}
		registry, e := registryName(kind, "skill", name)
		if e != nil {
			*warnings = append(*warnings, e.Error())
			return nil
		}
		d.Skills = append(d.Skills, Tool{Name: registry, Service: "harness", Source: string(kind), Selector: "skill:" + name, Executor: string(kind), Registration: "skill:" + name, OperationClass: "write", Description: description})
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("discover skills: %w", err)
	}
	return nil
}

func registryName(kind Kind, segments ...string) (string, error) {
	parts := []string{string(kind)}
	for _, segment := range segments {
		var b strings.Builder
		for _, r := range strings.ToLower(segment) {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
				b.WriteRune(r)
			} else {
				b.WriteByte('_')
			}
		}
		if b.Len() == 0 {
			return "", fmt.Errorf("empty normalized tool name")
		}
		parts = append(parts, b.String())
	}
	name := strings.Join(parts, ".")
	if len(name) > 128 {
		return "", fmt.Errorf("tool name exceeds 128 characters")
	}
	return name, nil
}

func filterDuplicateNames(d *Discovery) {
	seen := map[string]bool{}
	filter := func(group []Tool) []Tool {
		out := group[:0]
		for _, t := range group {
			if seen[t.Name] {
				d.Warnings = append(d.Warnings, "duplicate normalized tool name: "+t.Name)
				continue
			}
			seen[t.Name] = true
			out = append(out, t)
		}
		return out
	}
	d.BuiltIns = filter(d.BuiltIns)
	d.Skills = filter(d.Skills)
	d.MCP = filter(d.MCP)
	if len(d.Warnings) == 0 {
		d.Warnings = nil
	}
}
