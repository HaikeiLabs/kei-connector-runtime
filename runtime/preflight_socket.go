package runtime

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
)

const (
	preflightRequestSchema  = "kei.tool-preflight-request/v1"
	preflightResponseSchema = "kei.tool-preflight-response/v1"
	consumeRequestSchema    = "kei.operation-consume-request/v1"
	consumeResponseSchema   = "kei.operation-consume-response/v1"
)

// RegisterOperationPlanner installs trusted typed route metadata and the
// matching validator/planner. It is intentionally a runtime registration seam
// for HAI-392; callers cannot supply route metadata in socket requests.
func (l *LocalPDP) RegisterOperationPlanner(tool string, registration ToolOperationRegistration) error {
	if tool == "" || registration.AgentID == "" || !registration.Route.valid() || registration.Validator == nil || registration.Planner == nil {
		return ErrPlanInvalid
	}
	l.registrationsMu.Lock()
	defer l.registrationsMu.Unlock()
	if _, exists := l.registrations[tool]; exists {
		return errors.New("operation planner already registered")
	}
	registration.Route = cloneBinding(BindingContext{Route: registration.Route}).Route
	l.registrations[tool] = registration
	return nil
}

type socketPreflightRequest struct {
	Schema          string          `json:"schema"`
	Tool            string          `json:"tool"`
	Args            json.RawMessage `json:"args"`
	ParentSpan      string          `json:"parent_span,omitempty"`
	DelegationDepth int             `json:"delegation_depth,omitempty"`
}
type socketPreflightResponse struct {
	Schema     string    `json:"schema"`
	Decision   string    `json:"decision"`
	ReasonCode string    `json:"reason_code,omitempty"`
	Handle     string    `json:"handle,omitempty"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
}
type socketConsumeRequest struct {
	Schema          string    `json:"schema"`
	Handle          string    `json:"handle"`
	Tool            string    `json:"tool"`
	ParentSpan      string    `json:"parent_span,omitempty"`
	DelegationDepth int       `json:"delegation_depth,omitempty"`
	Operation       Operation `json:"operation"`
}
type socketConsumeResponse struct {
	Schema   string `json:"schema"`
	Decision string `json:"decision"`
}

func (l *LocalPDP) handlePreflight(w http.ResponseWriter, r *http.Request) {
	var req socketPreflightRequest
	if decodeSocketJSON(w, r, &req) != nil || req.Schema != preflightRequestSchema || req.Tool == "" || len(req.Args) == 0 || req.DelegationDepth < 0 || req.DelegationDepth > 32 {
		writeRuntimeError(w, http.StatusBadRequest, "invalid_request", "request must contain a tool and invocation args")
		return
	}
	l.registrationsMu.RLock()
	registration, ok := l.registrations[req.Tool]
	l.registrationsMu.RUnlock()
	if !ok {
		l.writePreflightDeny(w, "planner_unavailable")
		return
	}
	e := l.evaluator.Load()
	identity := l.identity.Load()
	subject, hasSubject := l.Sessions.Current()
	if e == nil || identity == nil || identity.WorkspaceID == nil || !hasSubject || subject.UserID == "" {
		l.writePreflightDeny(w, "preflight_unavailable")
		return
	}
	validated, err := registration.Validator.ValidateArgs(req.Args)
	if err != nil || len(validated) == 0 {
		l.writePreflightDeny(w, "input_invalid")
		return
	}
	digest, err := e.CurrentBundleDigest(r.Context())
	if err != nil {
		l.writePreflightDeny(w, "policy_bundle_missing")
		return
	}
	binding := BindingContext{InstallationID: identity.ID, BundleDigest: digest, Subject: subject.UserID, AgentID: registration.AgentID, Tool: req.Tool, Route: registration.Route, ParentSpan: req.ParentSpan, DelegationDepth: req.DelegationDepth}
	grant, err := l.authorizations.Preflight(PreflightInput{Binding: binding, ValidatedArgs: validated, Planner: registration.Planner, Authorizer: e}, 15*time.Second)
	if err != nil {
		l.writePreflightDeny(w, "preflight_denied")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(socketPreflightResponse{Schema: preflightResponseSchema, Decision: "permit", Handle: grant.Handle, ExpiresAt: grant.ExpiresAt})
}
func (l *LocalPDP) writePreflightDeny(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(socketPreflightResponse{Schema: preflightResponseSchema, Decision: "deny", ReasonCode: reason})
}
func (l *LocalPDP) handleConsume(w http.ResponseWriter, r *http.Request) {
	var req socketConsumeRequest
	if decodeSocketJSON(w, r, &req) != nil || req.Schema != consumeRequestSchema || req.Handle == "" || req.Tool == "" {
		writeRuntimeError(w, http.StatusBadRequest, "invalid_request", "request must contain a handle, tool and operation")
		return
	}
	l.registrationsMu.RLock()
	registration, ok := l.registrations[req.Tool]
	l.registrationsMu.RUnlock()
	e := l.evaluator.Load()
	identity := l.identity.Load()
	subject, hasSubject := l.Sessions.Current()
	if !ok || e == nil || identity == nil || !hasSubject || subject.UserID == "" {
		l.writeConsumeDeny(w)
		return
	}
	digest, err := e.CurrentBundleDigest(r.Context())
	if err != nil {
		l.writeConsumeDeny(w)
		return
	}
	binding := BindingContext{InstallationID: identity.ID, BundleDigest: digest, Subject: subject.UserID, AgentID: registration.AgentID, Tool: req.Tool, Route: registration.Route, ParentSpan: req.ParentSpan, DelegationDepth: req.DelegationDepth}
	if l.authorizations.Consume(req.Handle, binding, req.Operation) != nil {
		l.writeConsumeDeny(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(socketConsumeResponse{Schema: consumeResponseSchema, Decision: "permit"})
}
func (l *LocalPDP) writeConsumeDeny(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(socketConsumeResponse{Schema: consumeResponseSchema, Decision: "deny"})
}

// Keep the compile-time contract explicit as HAI-392's registration layer is
// wired into LocalPDP.
var _ OperationAuthorizer = (*pdp.Evaluator)(nil)
