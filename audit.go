package connectorruntime

import (
	"encoding/json"
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

// appendDecisionEvent appends e as a single JSON line to the audit spool at
// path, capped at maxBytes in total (0 uses the default cap). Appends are
// serialized by the spool lock, so concurrent proxy invocations each write a
// whole line. An empty path is a no-op.
func appendDecisionEvent(path string, maxBytes int64, e DecisionEvent) error {
	if path == "" {
		return nil
	}
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return newAuditSpool(path, maxBytes).Append(eventClassDecision, data)
}

// emitDecision best-effort appends e to the audit spool at path. A failure
// (missing dir, read-only fs, ...) never affects the authorize decision.
func emitDecision(path string, maxBytes int64, e DecisionEvent) {
	_ = appendDecisionEvent(path, maxBytes, e)
}

// LifecycleEvent is a runtime lifecycle audit record written by the heartbeat
// loop. It is appended as a single JSON line to the same local JSONL spool as
// decisions, where the collector routes it to the lifecycle flush endpoint.
type LifecycleEvent struct {
	EventClass     string            `json:"event_class"`
	SchemaVersion  int               `json:"schema_version"`
	EventType      string            `json:"event_type"`
	Outcome        HeartbeatOutcome  `json:"outcome"`
	ObservedAt     time.Time         `json:"observed_at"`
	RuntimeVersion string            `json:"runtime_version"`
	RunID          string            `json:"run_id"`
	Seq            uint64            `json:"seq"`
	Attrs          map[string]string `json:"attrs,omitempty"`
}

// appendLifecycleEvent marshals e and appends it to the audit spool at path,
// capped by maxBytes. A lifecycle record is refused if the spool nears its cap
// (see lifecycleCeilingPercent). An empty path is a no-op.
func appendLifecycleEvent(path string, maxBytes int64, e LifecycleEvent) error {
	if path == "" {
		return nil
	}
	e.EventClass = eventClassLifecycle
	e.SchemaVersion = 1
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return newAuditSpool(path, maxBytes).Append(eventClassLifecycle, data)
}
