package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// DecisionEvent is the canonical identity-propagation audit record emitted for
// every authorize decision. It is appended as a single JSON line to a local
// JSONL file; the collector subcommand ships these lines to ABAC's
// audit_records table. Its JSON shape matches ABAC's AuditRecord exactly so a
// record forwards unchanged. It never carries credential material.
type DecisionEvent struct {
	SpanID           string    `json:"span_id"`
	InvokedAt        time.Time `json:"invoked_at"`
	InvokingSubject  string    `json:"invoking_subject"`
	ParentSpan       *string   `json:"parent_span,omitempty"`
	DelegationDepth  int       `json:"delegation_depth"`
	AgentID          string    `json:"agent_id"`
	AgentVersion     *string   `json:"agent_version,omitempty"`
	Framework        string    `json:"framework"`
	ToolName         string    `json:"tool_name"`
	ToolArgsDigest   *string   `json:"tool_args_digest,omitempty"`
	ResourcesTouched []string  `json:"resources_touched"`
	Decision         string    `json:"decision"`
	PolicyID         *string   `json:"policy_id,omitempty"`
	PolicyReason     *string   `json:"policy_reason,omitempty"`
	OrgID            *string   `json:"org_id,omitempty"`
	WorkspaceID      *string   `json:"workspace_id,omitempty"`
}

// appendDecisionEvent appends e as a single JSON line to the JSONL file at
// path. The file is opened in append mode so concurrent proxy invocations each
// write an atomic line. An empty path is a no-op.
func appendDecisionEvent(path string, e DecisionEvent) error {
	if path == "" {
		return nil
	}
	// The spool is normally written under a mounted volume (e.g.
	// /data/kei-proxy on the bot's PVC); create the parent directory so a
	// fresh volume mount doesn't fail the first authorized call.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err = f.Write(append(data, '\n')); err != nil {
		return err
	}
	// The JSONL file is the fail-open durability boundary. Do not report the
	// authorization decision as auditable until the appended line has reached
	// stable storage according to the filesystem's sync semantics.
	return f.Sync()
}

// emitDecision best-effort appends e to the JSONL file at path. A failure
// (missing dir, read-only fs, ...) never affects the authorize decision.
func emitDecision(path string, e DecisionEvent) {
	_ = appendDecisionEvent(path, e)
}
