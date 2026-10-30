package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

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

// UnauthenticatedSubject is the legacy-format (no colon) subject stamped on
// audit records that have no resolved subject. The catalog's audit:flush
// rejects empty invoking_subject values, so a deny without a subject must
// still carry a stable, non-empty value. It is a fixed default, never derived
// from the agent or any other identity.
const UnauthenticatedSubject = "unauthenticated"

// SubjectOrDefault returns subject when it is non-empty, otherwise
// UnauthenticatedSubject. It is the single place that decides the default so
// every deny path that can produce an empty subject stamps the same value.
func SubjectOrDefault(subject string) string {
	if subject == "" {
		return UnauthenticatedSubject
	}
	return subject
}

type DecisionEvent struct {
	SpanID              string    `json:"span_id"`
	InvokedAt           time.Time `json:"invoked_at"`
	InvokingSubject     string    `json:"invoking_subject"`
	ParentSpan          *string   `json:"parent_span,omitempty"`
	DelegationDepth     int       `json:"delegation_depth"`
	AgentID             string    `json:"agent_id"`
	AgentVersion        *string   `json:"agent_version,omitempty"`
	Framework           string    `json:"framework"`
	ToolName            string    `json:"tool_name"`
	ToolArgsDigest      *string   `json:"tool_args_digest,omitempty"`
	ResourcesTouched    []string  `json:"resources_touched"`
	Decision            string    `json:"decision"`
	PolicyID            *string   `json:"policy_id,omitempty"`
	PolicyReason        *string   `json:"policy_reason,omitempty"`
	OrgID               *string   `json:"org_id,omitempty"`
	WorkspaceID         *string   `json:"workspace_id,omitempty"`
	PolicyBundleVersion *int64    `json:"policy_bundle_version,omitempty"`
	PolicyBundleDigest  *string   `json:"policy_bundle_digest,omitempty"`
	PolicyRevision      *int64    `json:"policy_revision,omitempty"`
	BundleState         string    `json:"bundle_state,omitempty"`
	DenySource          string    `json:"deny_source,omitempty"`
	ReasonCode          string    `json:"reason_code,omitempty"`
}

func AppendDecisionEvent(path string, maxBytes int64, e DecisionEvent) error {
	if path == "" {
		return nil
	}
	// The catalog's audit:flush rejects an empty invoking_subject, which
	// would pin the oldest spool batch on that record forever. Stamp the
	// same default the socket path uses, so every writer that funnels
	// through here (one-shot EmitDecision, legacy pedro records, external
	// callers) emits a shippable value (HAI-928).
	e.InvokingSubject = SubjectOrDefault(e.InvokingSubject)
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return NewAuditSpool(path, maxBytes).Append(EventClassDecision, data)
}

func EmitDecision(path string, maxBytes int64, e DecisionEvent) {
	if err := AppendDecisionEvent(path, maxBytes, e); err != nil {
		fmt.Fprintf(os.Stderr, "audit: failed to append decision event: %v\n", err)
	}
}

// PolicyBootstrapEvent builds the allowlisted bootstrap audit record. Sync errors
// are deliberately reduced to a stable reason code; error text may contain
// provider response details and must never enter lifecycle audit.
func PolicyBootstrapEvent(syncErr error, version int64, digest, runtimeVersion, runID string, observedAt time.Time) LifecycleEvent {
	outcome := HeartbeatOK
	attrs := map[string]string{}
	if syncErr != nil {
		outcome = HeartbeatCatalogError
		attrs["reason_code"] = "policy_sync_failed"
	} else {
		attrs["bundle_version"] = fmt.Sprintf("%d", version)
		attrs["bundle_digest"] = digest
	}
	return LifecycleEvent{
		EventType: "policy_bundle_bootstrap", Outcome: outcome, ObservedAt: observedAt,
		RuntimeVersion: runtimeVersion, RunID: runID, Seq: 1, Attrs: attrs,
	}
}

func AppendLifecycleEvent(path string, maxBytes int64, e LifecycleEvent) error {
	if path == "" {
		return nil
	}
	e.EventClass = EventClassLifecycle
	e.SchemaVersion = 1
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return NewAuditSpool(path, maxBytes).Append(EventClassLifecycle, data)
}
