package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

// Error sentinels moved from root.
var (
	ErrEnrollmentRequired        = errors.New("enrollment required")
	ErrCredentialBindingNotFound = errors.New("credential binding not found")
)

// CredentialResponse carries only the secret value.
type CredentialResponse struct {
	Value string `json:"value"`
}

// AuthorizeOutput is the result of an authorize call.
type AuthorizeOutput struct {
	Decision   string              `json:"decision"`
	ReasonCode string              `json:"reason_code,omitempty"`
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

// OAuthTokenResponse is the response from the OIDC bridge.
type OAuthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Provider    string `json:"provider"`
	Identity    string `json:"identity"`
}

// ToolRegistry is the subset of Registry needed for authorization.
type ToolRegistry interface {
	Service(tool string) string
}

// CredentialResolver resolves credential bindings from the control plane.
type CredentialResolver interface {
	Resolve(ctx context.Context, runtimeToken, userID, service string) (*CredentialDescriptor, error)
}

// OIDCTokenProvider fetches OAuth tokens from the OIDC bridge.
type OIDCTokenProvider interface {
	GetOAuthToken(ctx context.Context, userID, provider string) (*OAuthTokenResponse, error)
}

// SecretGetter retrieves secret values from the customer's secret store.
type SecretGetter interface {
	Get(ctx context.Context, backend, secretRef string) (*string, error)
}

// AuthorizeParams carries everything AuthorizeTool needs.
type AuthorizeParams struct {
	Ctx               context.Context
	User              string
	ProviderUser      string
	Tool              string
	Action            string
	Resource          string
	Harness           string
	SpanID            string
	InvokingSubject   string
	ParentSpan        string
	DelegationDepth   int
	AgentID           string
	AgentVersion      string
	Framework         string
	ToolArgsDigest    string
	Resources         []string
	OrgID             string
	WorkspaceID       string
	AuditPath         string
	AuditMaxBytes     int64
	Registry          ToolRegistry
	CredentialBinding CredentialResolver
	SecretStore       SecretGetter
	OIDCBridge        OIDCTokenProvider
	PolicyBundle      *policybundle.Verified
	PolicySubject     *policybundle.Subject
	BundleState       string
}

// AuthorizeTool is the core authorization logic.
func AuthorizeTool(p AuthorizeParams) (AuthorizeOutput, error) {
	service := p.Registry.Service(p.Tool)

	resource := p.Resource
	if service != "" && !strings.HasPrefix(resource, service+":") {
		resource = service + ":repo:" + resource
	}

	var resp *AuthorizeResponse
	var localDecision *policybundle.Decision
	if p.PolicyBundle != nil {
		subjectID := p.User
		if p.PolicySubject != nil && p.PolicySubject.UserID != "" {
			subjectID = p.PolicySubject.UserID
		}
		decision := p.PolicyBundle.Evaluate(policybundle.Call{Tool: p.Tool, Action: p.Action, Resource: resource, AgentID: p.AgentID, UserID: subjectID}, p.PolicySubject)
		localDecision = &decision
		resp = &AuthorizeResponse{Decision: decision.Outcome, Reason: decision.Reason, PolicyID: decision.PolicyID, ReasonCode: decision.ReasonCode}
		if p.PolicySubject != nil && len(p.PolicySubject.Enrollment) > 0 {
			enrollment := json.RawMessage(p.PolicySubject.Enrollment)
			resp.Enrollment = &enrollment
		}
		if decision.Outcome == "deny" && decision.ReasonCode == "enrollment_required" {
			resp.Decision = "enrollment_required"
		}
	} else {
		return AuthorizeOutput{Decision: "deny", ReasonCode: "policy_bundle_missing", DenySource: "runtime_state", Reason: "no verified local policy bundle"}, nil
	}

	out := AuthorizeOutput{}
	if localDecision != nil {
		out.ReasonCode = localDecision.ReasonCode
		if localDecision.ReasonCode != "" {
			out.DenySource = "policy"
			if localDecision.ReasonCode == "subject_resolution_unavailable" || strings.HasPrefix(localDecision.ReasonCode, "identity_") || localDecision.ReasonCode == "enrollment_required" {
				out.DenySource = "identity"
			}
			if strings.HasPrefix(localDecision.ReasonCode, "policy_bundle_") {
				out.DenySource = "runtime_state"
			}
			if localDecision.ReasonCode == "tool_not_registered" || localDecision.ReasonCode == "tool_action_mismatch" || strings.HasPrefix(localDecision.ReasonCode, "agent_") {
				out.DenySource = "registry"
			}
		}
	}
	switch resp.Decision {
	case "allow":
		out.Decision = "allow"
		if service == "" {
			break
		}

		if p.OIDCBridge != nil {
			oauthToken, err := p.OIDCBridge.GetOAuthToken(p.Ctx, p.User, service)
			if err != nil {
				if errors.Is(err, ErrEnrollmentRequired) {
					slog.Info("OIDC bridge enrollment required", "user_id", p.User, "service", service, "error", err)
					out.Decision = "enrollment_required"
					out.Service = service
					break
				}
				slog.Warn("OIDC bridge error", "user_id", p.User, "service", service, "error", err)
			}
			if oauthToken != nil {
				out.Credential = &CredentialResponse{Value: oauthToken.AccessToken}
				out.Service = service
				break
			}
		}

		var cred *string
		if p.CredentialBinding != nil {
			descriptor, err := p.CredentialBinding.Resolve(p.Ctx, p.Harness, p.User, service)
			if err != nil {
				if errors.Is(err, ErrCredentialBindingNotFound) {
					slog.Info("credential binding enrollment required", "user_id", p.User, "service", service)
				} else {
					slog.Warn("credential binding lookup error", "user_id", p.User, "service", service, "error", err)
				}
				out.Decision = "enrollment_required"
				out.Service = service
				break
			}
			cred, err = p.SecretStore.Get(p.Ctx, descriptor.SecretBackend, descriptor.SecretRef)
			if err != nil {
				out.Decision = "enrollment_required"
				out.Service = service
				break
			}
		}
		if cred == nil {
			out.Decision = "enrollment_required"
			out.Service = service
			break
		}
		out.Credential = &CredentialResponse{Value: *cred}
	case "enrollment_required":
		out.Decision = "deny"
		out.Reason = resp.Reason
		out.Enrollment = resp.Enrollment
		out.Connect = resp.Connect
	default:
		out.Decision = "deny"
		out.Reason = resp.Reason
		out.Connect = resp.Connect
	}

	EmitDecision(p.AuditPath, p.AuditMaxBytes, BuildDecisionEvent(p, resp, out, resource))

	return out, nil
}

// BuildDecisionEvent assembles the canonical audit record for an authorize decision.
func BuildDecisionEvent(p AuthorizeParams, resp *AuthorizeResponse, out AuthorizeOutput, resource string) DecisionEvent {
	spanID := p.SpanID
	if spanID == "" {
		spanID = uuid.NewString()
	}

	subject := p.InvokingSubject
	if subject == "" {
		subject = p.User
	}

	resources := p.Resources
	if len(resources) == 0 && resource != "" {
		resources = []string{resource}
	}

	event := DecisionEvent{
		SpanID:           spanID,
		InvokedAt:        time.Now().UTC(),
		InvokingSubject:  subject,
		DelegationDepth:  p.DelegationDepth,
		AgentID:          p.AgentID,
		Framework:        p.Framework,
		ToolName:         p.Tool,
		ResourcesTouched: resources,
		Decision:         out.Decision,
	}
	if p.ParentSpan != "" {
		event.ParentSpan = &p.ParentSpan
	}
	if p.AgentVersion != "" {
		event.AgentVersion = &p.AgentVersion
	}
	if p.ToolArgsDigest != "" {
		event.ToolArgsDigest = &p.ToolArgsDigest
	}
	if p.PolicyBundle != nil {
		version := p.PolicyBundle.Payload.BundleVersion
		revision := p.PolicyBundle.Payload.PolicyRevision
		digest := p.PolicyBundle.Digest
		event.PolicyBundleVersion = &version
		event.PolicyRevision = &revision
		event.PolicyBundleDigest = &digest
		event.BundleState = p.BundleState
	}
	if out.DenySource != "" {
		event.DenySource = out.DenySource
	}
	if out.ReasonCode != "" {
		event.ReasonCode = out.ReasonCode
	}
	if resp != nil {
		if resp.OrgID != nil {
			event.OrgID = resp.OrgID
		} else if p.OrgID != "" {
			event.OrgID = &p.OrgID
		}
		if resp.PolicyID != "" {
			event.PolicyID = &resp.PolicyID
		}
		if resp.Reason != "" {
			event.PolicyReason = &resp.Reason
		}
	}
	if resp != nil && resp.WorkspaceID != nil {
		event.WorkspaceID = resp.WorkspaceID
	} else if p.WorkspaceID != "" {
		event.WorkspaceID = &p.WorkspaceID
	}
	return event
}

// WritePolicyStateDenial writes a deny output and returns exit code 1.
func WritePolicyStateDenial(stdout, stderr io.Writer, reason string, err error) int {
	source := "runtime_state"
	if reason == "subject_resolution_unavailable" || reason == "enrollment_required" || strings.HasPrefix(reason, "identity_") {
		source = "identity"
	}
	_ = WriteJSON(stdout, AuthorizeOutput{Decision: "deny", ReasonCode: reason, DenySource: source, Reason: reason})
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

// SplitCSV splits a comma-separated string into trimmed, non-empty fields.
func SplitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
