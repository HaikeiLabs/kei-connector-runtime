package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

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
