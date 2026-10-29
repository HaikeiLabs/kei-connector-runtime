package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/denyhint"
)

// ErrCredentialBindingNotFound is the sentinel moved from root.
var ErrCredentialBindingNotFound = errors.New("credential binding not found")

// CredentialResponse carries only the secret value.
type CredentialResponse struct {
	Value string `json:"value"`
}

// AuthorizeOutput is the result of an authorize call.
type AuthorizeOutput struct {
	Decision   string              `json:"decision"`
	ReasonCode string              `json:"reason_code,omitempty"`
	Hint       string              `json:"hint,omitempty"`
	DenySource string              `json:"deny_source,omitempty"`
	Reason     string              `json:"reason,omitempty"`
	Service    string              `json:"service,omitempty"`
	Credential *CredentialResponse `json:"credential,omitempty"`
	Enrollment *json.RawMessage    `json:"enrollment,omitempty"`
	Connect    *json.RawMessage    `json:"connect,omitempty"`
}

// AuthorizeResponse is the local decision result and audit adapter shape.
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

// CredentialDescriptor is non-secret metadata resolved from the Kei control
// plane. The secret value is fetched separately from the customer's store.
type CredentialDescriptor struct {
	ID                  string         `json:"id"`
	OrgID               string         `json:"org_id"`
	UserID              string         `json:"user_id"`
	Service             string         `json:"service"`
	SecretBackend       string         `json:"secret_backend"`
	SecretRef           string         `json:"secret_ref"`
	CredentialType      string         `json:"credential_type,omitempty"`
	InjectionType       string         `json:"injection_type,omitempty"`
	InjectionHeader     string         `json:"injection_header,omitempty"`
	InjectionQueryParam string         `json:"injection_query_param,omitempty"`
	Status              string         `json:"status"`
	Version             int            `json:"version"`
	Metadata            map[string]any `json:"metadata,omitempty"`
}

// CredentialResolver resolves credential bindings from the control plane.
type CredentialResolver interface {
	Resolve(ctx context.Context, runtimeToken, userID, service string) (*CredentialDescriptor, error)
}

// WritePolicyStateDenial writes a deny output and returns exit code 1.
func WritePolicyStateDenial(stdout, stderr io.Writer, reason string, err error) int {
	source := "runtime_state"
	if reason == "subject_resolution_unavailable" || reason == "enrollment_required" || strings.HasPrefix(reason, "identity_") {
		source = "identity"
	}
	_ = WriteJSON(stdout, AuthorizeOutput{Decision: "deny", ReasonCode: reason, DenySource: source, Reason: reason, Hint: denyhint.Hint(reason)})
	if err != nil {
		var failure *SubjectResolutionFailure
		if reason == "subject_resolution_unavailable" && errors.As(err, &failure) {
			if failure.HTTPStatus != 0 {
				fmt.Fprintf(stderr, "authorization denied (%s): category=%s http_status=%d\n", reason, failure.Category, failure.HTTPStatus)
			} else if failure.TransportPhase != "" || failure.TransportKind != "" {
				diagnostic := fmt.Sprintf("authorization denied (%s): category=%s", reason, failure.Category)
				if failure.TransportPhase != "" {
					diagnostic += " transport_phase=" + failure.TransportPhase
				}
				if failure.TransportKind != "" {
					diagnostic += " transport_kind=" + failure.TransportKind
				}
				fmt.Fprintln(stderr, diagnostic)
			} else {
				fmt.Fprintf(stderr, "authorization denied (%s): category=%s\n", reason, failure.Category)
			}
		} else {
			fmt.Fprintf(stderr, "authorization denied (%s): %v\n", reason, err)
		}
	}
	return 1
}
