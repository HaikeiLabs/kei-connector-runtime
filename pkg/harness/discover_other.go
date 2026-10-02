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

type CodexAdapter struct{}

func (CodexAdapter) Kind() Kind { return Codex }
func (CodexAdapter) DiscoverTools(ctx context.Context, env Env) (Discovery, error) {
	root := env.HomeDir
	if root == "" {
		root, _ = os.UserHomeDir()
	}
	if root == "" {
		return Discovery{}, errors.New("home directory is required")
	}
	config := env.ConfigDir
	if config == "" {
		config = filepath.Join(root, ".codex")
	}
	builtins, err := builtinsForKind(Codex)
	if err != nil {
		return Discovery{}, err
	}
	d := Discovery{BuiltIns: builtins}
	// Codex MCP config is TOML. Parse server table names and cached tool
	// declarations without starting the configured server processes.
	paths := []string{filepath.Join(config, "config.toml")}
	if env.ProjectDir != "" {
		paths = append(paths, filepath.Join(env.ProjectDir, ".codex", "config.toml"))
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return Discovery{}, fmt.Errorf("read Codex config: %w", err)
		}
		server := ""
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "[mcp_servers.") && strings.HasSuffix(line, "]") {
				server = strings.TrimSuffix(strings.TrimPrefix(line, "[mcp_servers."), "]")
				name, e := registryName(Codex, "mcp", server)
				if e != nil {
					d.Warnings = append(d.Warnings, e.Error())
					continue
				}
				d.MCP = append(d.MCP, Tool{Name: name, Source: "mcp", Selector: "mcp:" + server, OperationClass: "write", Description: "MCP server " + server})
			}
		}
	}
	var warnings []string
	skillDirs := []string{filepath.Join(config, "skills"), filepath.Join(root, ".agents", "skills")}
	if env.ProjectDir != "" {
		skillDirs = append(skillDirs, filepath.Join(env.ProjectDir, ".agents", "skills"))
	}
	for _, dir := range skillDirs {
		if e := discoverSkills(ctx, dir, Codex, &d, &warnings); e != nil {
			return Discovery{}, e
		}
	}
	d.Warnings = append(d.Warnings, warnings...)
	filterDuplicateNames(&d)
	return d, nil
}
func (CodexAdapter) RenderPolicy(ctx context.Context, env Env, b VerifiedBundle, h Harness) (RenderPlan, error) {
	h.Kind = Codex
	return renderPolicy(ctx, env, b, h)
}
func (CodexAdapter) Hook(ctx context.Context, rec Recorder, h Harness, stdin io.Reader, stdout io.Writer) error {
	return reportHook(ctx, rec, h, stdin, stdout)
}

type OpenCodeAdapter struct{}

func (OpenCodeAdapter) Kind() Kind { return OpenCode }
func (OpenCodeAdapter) DiscoverTools(ctx context.Context, env Env) (Discovery, error) {
	root := env.HomeDir
	if root == "" {
		root, _ = os.UserHomeDir()
	}
	if root == "" {
		return Discovery{}, errors.New("home directory is required")
	}
	config := env.ConfigDir
	if config == "" {
		config = filepath.Join(root, ".config", "opencode")
	}
	builtins, err := builtinsForKind(OpenCode)
	if err != nil {
		return Discovery{}, err
	}
	d := Discovery{BuiltIns: builtins}
	paths := []string{filepath.Join(config, "opencode.json"), filepath.Join(root, "opencode.json")}
	if env.ProjectDir != "" {
		paths = append(paths, filepath.Join(env.ProjectDir, ".opencode", "opencode.json"))
	}
	for _, path := range paths {
		b, e := os.ReadFile(path)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return Discovery{}, fmt.Errorf("read opencode config: %w", e)
		}
		var cfg struct {
			MCP map[string]struct {
				Type    string `json:"type"`
				Enabled *bool  `json:"enabled"`
				Tools   []struct {
					Name        string `json:"name"`
					Description string `json:"description"`
					ReadOnly    bool   `json:"readOnly"`
				} `json:"tools"`
			} `json:"mcp"`
		}
		if e = json.Unmarshal(b, &cfg); e != nil {
			d.Warnings = append(d.Warnings, "invalid opencode.json")
			continue
		}
		servers := make([]string, 0, len(cfg.MCP))
		for server := range cfg.MCP {
			servers = append(servers, server)
		}
		sort.Strings(servers)
		for _, server := range servers {
			s := cfg.MCP[server]
			if s.Enabled != nil && !*s.Enabled {
				continue
			}
			if len(s.Tools) == 0 {
				name, e := registryName(OpenCode, "mcp", server)
				if e != nil {
					d.Warnings = append(d.Warnings, e.Error())
					continue
				}
				d.MCP = append(d.MCP, Tool{Name: name, Source: "mcp", Selector: "mcp:" + server, OperationClass: "write", Description: "MCP server " + server})
				continue
			}
			for _, mt := range s.Tools {
				name, e := registryName(OpenCode, "mcp", server, mt.Name)
				if e != nil {
					d.Warnings = append(d.Warnings, e.Error())
					continue
				}
				class := "write"
				if mt.ReadOnly {
					class = "read"
				}
				d.MCP = append(d.MCP, Tool{Name: name, Source: "mcp", Selector: "mcp:" + server + "." + mt.Name, OperationClass: class, Description: mt.Description})
			}
		}
	}
	var warnings []string
	skillDirs := []string{filepath.Join(config, "skills"), filepath.Join(root, ".agents", "skills")}
	if env.ProjectDir != "" {
		skillDirs = append(skillDirs, filepath.Join(env.ProjectDir, ".opencode", "skills"))
	}
	for _, dir := range skillDirs {
		if e := discoverSkills(ctx, dir, OpenCode, &d, &warnings); e != nil {
			return Discovery{}, e
		}
	}
	d.Warnings = append(d.Warnings, warnings...)
	filterDuplicateNames(&d)
	return d, nil
}
func (OpenCodeAdapter) RenderPolicy(ctx context.Context, env Env, b VerifiedBundle, h Harness) (RenderPlan, error) {
	h.Kind = OpenCode
	return renderPolicy(ctx, env, b, h)
}
func (OpenCodeAdapter) Hook(ctx context.Context, rec Recorder, h Harness, stdin io.Reader, stdout io.Writer) error {
	return reportHook(ctx, rec, h, stdin, stdout)
}

var _ Adapter = ClaudeCodeAdapter{}
var _ Adapter = CodexAdapter{}
var _ Adapter = OpenCodeAdapter{}
