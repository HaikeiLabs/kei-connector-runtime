package connectorruntime

import "encoding/json"

// AuthorizeResponse is retained as the local decision result and audit
// adapter shape. Runtime authorization no longer posts this request to a
// catalog decision endpoint.
type AuthorizeResponse struct {
	Decision    string           `json:"decision"`
	Reason      string           `json:"reason,omitempty"`
	ReasonCode  string           `json:"reason_code,omitempty"`
	DenySource  string           `json:"deny_source,omitempty"`
	OrgID       *string          `json:"org_id,omitempty"`
	UserID      *string          `json:"user_id,omitempty"`
	PolicyID    string           `json:"policy_id,omitempty"`
	WorkspaceID *string          `json:"workspace_id,omitempty"`
	Enrollment  *json.RawMessage `json:"enrollment,omitempty"`
	Connect     *json.RawMessage `json:"connect,omitempty"`
}
