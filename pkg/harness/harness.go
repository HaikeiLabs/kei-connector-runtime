// Package harness describes installed AI coding harnesses and renders their
// native policy configuration. Adapters discover metadata and produce plans;
// they never evaluate tool calls or grant capabilities.
package harness

import (
	"context"
	"io"
	"time"
)

// Kind identifies a supported harness implementation.
type Kind = string

const (
	ClaudeCode Kind = "claude_code"
	Codex      Kind = "codex"
	OpenCode   Kind = "opencode"
)

// Env contains paths needed for read-only discovery and rendering. Empty paths
// use the adapter's documented defaults below HomeDir.
type Env struct {
	HomeDir    string
	ConfigDir  string
	ProjectDir string
}

// Harness identifies one harness registered to a runtime installation.
type Harness struct {
	ID      string `json:"id"`
	Kind    Kind   `json:"kind"`
	AgentID string `json:"agent_id,omitempty"`
}

// Tool is a discovered harness tool call. Selector preserves harness-native
// spelling for policy matching; Name is the normalized registry identifier.
type Tool struct {
	Name           string `json:"name"`
	Service        string `json:"service"`
	Source         string `json:"source"`
	Selector       string `json:"selector,omitempty"`
	Executor       string `json:"executor"`
	Registration   string `json:"registration"`
	OperationClass string `json:"operation_class"`
	Description    string `json:"description"`
}

// Discovery separates adapter-declared facts from local installed extensions.
type Discovery struct {
	BuiltIns []Tool   `json:"built_ins"`
	Skills   []Tool   `json:"skills"`
	MCP      []Tool   `json:"mcp"`
	Warnings []string `json:"warnings,omitempty"`
}

// VerifiedBundle is the narrow input adapters need from the runtime's
// verified policy bundle. PolicyJSON contains the canonical policy_set object;
// adapters do not verify, interpret, or evaluate it.
type VerifiedBundle struct {
	ID         string
	ExpiresAt  time.Time
	Digest     string
	PolicyJSON []byte
}

// Bundle is the verified policy snapshot consumed by renderers.
type Bundle = VerifiedBundle

// RenderPlan describes native config edits and hook installation. The shared
// applier owns backups, managed-block preservation, and expiry cleanup.
type RenderPlan struct {
	ConfigPath string
	Config     []byte
	HookPath   string
	Hook       []byte
	Files      []ManagedFile
	ExpiresAt  time.Time
	Managed    []ManagedEntry
	Warnings   []string
}

// ManagedFile is a complete harness-owned file installed from a render plan.
// The shared applier must back up an existing file before replacing it.
type ManagedFile struct {
	Path    string `json:"path"`
	Data    []byte `json:"data"`
	Replace bool   `json:"replace"`
}

// ManagedEntry carries an exact native config value and its expiry behavior.
// The applier records the value and bundle digest in its ledger before writing.
type ManagedEntry struct {
	Path           string    `json:"path"`
	Value          string    `json:"value"`
	Decision       string    `json:"decision"`
	PolicyID       string    `json:"policy_id,omitempty"`
	BundleDigest   string    `json:"bundle_digest"`
	RemoveOnExpiry bool      `json:"remove_on_expiry"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// Recorder accepts report-only harness events for the local audit spool.
type Recorder interface {
	RecordHarnessEvent(context.Context, HarnessToolEvent) error
}

// HarnessToolEvent is a normalized observation, not an authorization result.
type HarnessToolEvent struct {
	Schema            string    `json:"schema"`
	HarnessID         string    `json:"harness_id"`
	HarnessKind       Kind      `json:"harness_kind"`
	HarnessRegistered bool      `json:"harness_registered"`
	HarnessSessionID  string    `json:"harness_session_id,omitempty"`
	ToolUseID         string    `json:"tool_use_id,omitempty"`
	Phase             string    `json:"phase"`
	Tool              string    `json:"tool"`
	Registered        bool      `json:"registered"`
	Selector          string    `json:"selector,omitempty"`
	Argv0             string    `json:"argv0,omitempty"`
	ArgsDigest        string    `json:"args_digest,omitempty"`
	NativeDecision    string    `json:"native_decision"`
	ObservedAt        time.Time `json:"observed_at"`
}

// Adapter provides discovery, native config rendering, and report-only hook
// decoding for one harness kind.
type Adapter interface {
	Kind() Kind
	DiscoverTools(context.Context, Env) (Discovery, error)
	RenderPolicy(context.Context, Env, VerifiedBundle, Harness) (RenderPlan, error)
	Hook(context.Context, Recorder, Harness, io.Reader, io.Writer) error
}

// Renderer is the minimal seam used by kei harness sync. Render returns the
// config bytes for the selected harness; callers own backups and atomic writes.
type Renderer interface {
	Render(kind string, bundle Bundle, cfg []byte) ([]byte, error)
	HookSpec(kind string, harnessID string) ([]byte, error)
}

// ManifestTool maps discovery to the typed v3 catalog route contract.
type ManifestTool struct {
	Name           string    `json:"name"`
	Service        string    `json:"service"`
	Source         string    `json:"source"`
	OperationClass string    `json:"operation_class"`
	Route          ToolRoute `json:"route"`
	Description    string    `json:"description"`
}

type ToolRoute struct {
	HarnessExecutor HarnessExecutorRoute `json:"harness_executor"`
}

type HarnessExecutorRoute struct {
	Executor     string `json:"executor"`
	Registration string `json:"registration"`
}

type ResourceType struct {
	Type       string `json:"type"`
	ParentType string `json:"parent_type,omitempty"`
}

type ToolManifest struct {
	Schema string         `json:"schema"`
	Tools  []ManifestTool `json:"tools"`
}

// ManifestFromDiscovery creates the v3 body for the runtime tool sync path.
// Registration is metadata only and grants no access.
func ManifestFromDiscovery(discoveries ...Discovery) ToolManifest {
	m := ToolManifest{Schema: "kei.tool-manifest/v3", Tools: []ManifestTool{}}
	for _, d := range discoveries {
		for _, group := range [][]Tool{d.BuiltIns, d.Skills, d.MCP} {
			for _, t := range group {
				m.Tools = append(m.Tools, ManifestTool{Name: t.Name, Service: t.Service, Source: t.Source, OperationClass: t.OperationClass, Route: ToolRoute{HarnessExecutor: HarnessExecutorRoute{Executor: t.Executor, Registration: t.Registration}}, Description: t.Description})
			}
		}
	}
	return m
}
