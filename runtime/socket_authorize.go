package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
)

const (
	authorizeRequestSchema  = "kei.authorize-request/v1"
	authorizeResponseSchema = "kei.authorize-response/v1"
	sessionSchema           = "kei.session/v1"
	maxSocketRequest        = 64 << 10
)

type socketAuthorizeRequest struct {
	Schema          string                    `json:"schema"`
	Tool            string                    `json:"tool,omitempty"`
	Action          string                    `json:"action,omitempty"`
	Resource        string                    `json:"resource,omitempty"`
	AgentID         string                    `json:"agent_id,omitempty"`
	Connector       *socketAuthorizeConnector `json:"connector,omitempty"`
	SpanID          string                    `json:"span_id,omitempty"`
	ParentSpan      string                    `json:"parent_span,omitempty"`
	DelegationDepth int                       `json:"delegation_depth,omitempty"`
	Framework       string                    `json:"framework,omitempty"`
	ToolArgsDigest  string                    `json:"tool_args_digest,omitempty"`
}

type socketAuthorizeConnector struct {
	ConnectorID string `json:"connector_id"`
	Capability  string `json:"capability"`
}

type socketAuthorizeResponse struct {
	Schema              string          `json:"schema"`
	Decision            string          `json:"decision"`
	ReasonCode          string          `json:"reason_code,omitempty"`
	DenySource          string          `json:"deny_source,omitempty"`
	Reason              string          `json:"reason,omitempty"`
	PolicyID            string          `json:"policy_id,omitempty"`
	PolicyBundleVersion *int64          `json:"policy_bundle_version,omitempty"`
	PolicyBundleDigest  string          `json:"policy_bundle_digest,omitempty"`
	PolicyRevision      *int64          `json:"policy_revision,omitempty"`
	BundleState         string          `json:"bundle_state"`
	Enrollment          json.RawMessage `json:"enrollment,omitempty"`
}

type socketSessionRequest struct {
	Schema     string          `json:"schema"`
	UserID     string          `json:"user_id,omitempty"`
	Email      string          `json:"email,omitempty"`
	Status     string          `json:"status"`
	Enrollment json.RawMessage `json:"enrollment,omitempty"`
	Source     string          `json:"source,omitempty"`
	ExternalID string          `json:"external_id,omitempty"`
}

type EmitAuditFunc func(json.RawMessage)

type socketDecisionEvent struct {
	SpanID              string   `json:"span_id"`
	InvokedAt           string   `json:"invoked_at"`
	DelegationDepth     int      `json:"delegation_depth"`
	AgentID             string   `json:"agent_id"`
	Framework           string   `json:"framework"`
	ToolName            string   `json:"tool_name"`
	InvokingSubject     string   `json:"invoking_subject"`
	ResourcesTouched    []string `json:"resources_touched"`
	Decision            string   `json:"decision"`
	DenySource          string   `json:"deny_source"`
	ReasonCode          string   `json:"reason_code"`
	PolicyID            *string  `json:"policy_id,omitempty"`
	PolicyReason        *string  `json:"policy_reason,omitempty"`
	PolicyBundleVersion *int64   `json:"policy_bundle_version,omitempty"`
	PolicyBundleDigest  string   `json:"policy_bundle_digest,omitempty"`
	PolicyRevision      *int64   `json:"policy_revision,omitempty"`
	BundleState         string   `json:"bundle_state"`
	OrgID               *string  `json:"org_id,omitempty"`
	WorkspaceID         *string  `json:"workspace_id,omitempty"`
	ParentSpan          *string  `json:"parent_span,omitempty"`
	ToolArgsDigest      *string  `json:"tool_args_digest,omitempty"`
}

// SessionKeychain provides CLI login token storage and verification.
type SessionKeychain interface {
	// Token returns the Kei CLI login token from the OS keychain.
	Token() (string, error)
	// Verify checks the token with the Kei API whoami endpoint and returns the
	// user's identity.
	Verify(ctx context.Context, token string) (userID string, err error)
}

type LocalPDP struct {
	cfg       PolicyConfig
	Sessions  *pdp.Sessions
	evaluator atomic.Pointer[pdp.Evaluator]
	identity  atomic.Pointer[Identity]
	emit      EmitAuditFunc
	keychain  SessionKeychain
}

func NewLocalPDP(cfg PolicyConfig, emit EmitAuditFunc) *LocalPDP {
	return &LocalPDP{cfg: cfg, Sessions: pdp.NewSessions(), emit: emit}
}

func (l *LocalPDP) SetKeychain(k SessionKeychain) { l.keychain = k }

func (l *LocalPDP) SetIdentity(identity *Identity) {
	if identity == nil || identity.WorkspaceID == nil {
		return
	}
	e, err := pdp.New(l.cfg.PolicyStateDir(), pdp.Audience{InstallationID: identity.ID, OrgID: identity.OrgID, WorkspaceID: *identity.WorkspaceID}, l.Sessions)
	if err != nil {
		slog.Error("local policy evaluator unavailable; socket authorize denies", "error", err)
		return
	}
	l.identity.Store(identity)
	l.evaluator.Store(e)
}

func (l *LocalPDP) AfterSync(err error) {
	e := l.evaluator.Load()
	if errors.Is(err, ErrInstallationRevoked) {
		if e != nil {
			e.RevokeSession()
		} else {
			l.Sessions.End()
		}
		return
	}
	if e != nil {
		e.ReconcileSession()
	}
}

func (l *LocalPDP) NewHandler(next http.Handler, checkConfig func() error, checkAuth func(*http.Request) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/authorize" && r.Method == http.MethodPost:
		case r.URL.Path == "/v1/session" && (r.Method == http.MethodPut || r.Method == http.MethodDelete || r.Method == http.MethodGet):
		default:
			next.ServeHTTP(w, r)
			return
		}
		if err := checkConfig(); err != nil {
			writeRuntimeError(w, http.StatusServiceUnavailable, "runtime_not_configured", err.Error())
			return
		}
		if !checkAuth(r) {
			writeRuntimeError(w, http.StatusUnauthorized, "invalid_runtime_token", "runtime authentication failed")
			return
		}
		switch {
		case r.URL.Path == "/v1/authorize":
			l.handleAuthorize(w, r)
		case r.Method == http.MethodPut:
			l.handleSessionStart(w, r)
		case r.Method == http.MethodGet:
			l.handleSessionGet(w, r)
		default:
			l.Sessions.End()
			w.WriteHeader(http.StatusNoContent)
		}
	})
}

func (l *LocalPDP) handleSessionStart(w http.ResponseWriter, r *http.Request) {
	var req socketSessionRequest
	if err := decodeSocketJSON(w, r, &req); err != nil || req.Schema != sessionSchema {
		writeRuntimeError(w, http.StatusBadRequest, "invalid_request", "request must be a "+sessionSchema+" object with no unknown fields")
		return
	}
	if req.UserID != "" || req.Email != "" || req.Status != "" {
		writeRuntimeError(w, http.StatusBadRequest, "invalid_session", "the user_id/email/status fields are no longer supported; use source/external_id")
		return
	}
	if req.Source == "" {
		writeRuntimeError(w, http.StatusBadRequest, "invalid_session", "a source is required")
		return
	}
	var sub pdp.Subject
	switch req.Source {
	case "cli":
		if l.keychain == nil {
			writeRuntimeError(w, http.StatusBadRequest, "invalid_session", "cli source not available")
			return
		}
		token, err := l.keychain.Token()
		if err != nil || token == "" {
			writeRuntimeError(w, http.StatusBadRequest, "invalid_session", "no cli login token found")
			return
		}
		userID, err := l.keychain.Verify(r.Context(), token)
		if err != nil {
			writeRuntimeError(w, http.StatusBadRequest, "invalid_session", "cli token verification failed: "+err.Error())
			return
		}
		sub = pdp.Subject{UserID: userID, Status: pdp.StatusLinked, Token: token}
	default:
		if req.ExternalID == "" {
			writeRuntimeError(w, http.StatusBadRequest, "invalid_session", "external_id is required for source "+req.Source)
			return
		}
		e := l.evaluator.Load()
		if e == nil {
			sub = pdp.Subject{Status: pdp.StatusUnlinked}
		} else {
			sub = resolveBundleSubject(e, req.Source, req.ExternalID)
		}
	}
	if err := l.Sessions.Start(sub); err != nil {
		writeRuntimeError(w, http.StatusBadRequest, "invalid_session", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// resolveBundleSubject looks up (source, external_id) in the evaluator's
// current bundle identities. When the identity is linked the returned subject
// carries the user id and linked status; otherwise it carries the identity's
// status (unlinked, pending, cross_workspace, revoked). An unknown or expired
// identity yields an unlinked subject.
func resolveBundleSubject(e *pdp.Evaluator, source, externalID string) pdp.Subject {
	for _, id := range e.BundleIdentities() {
		if id.Source != source || id.ExternalID != externalID {
			continue
		}
		if !id.ExpireTime.IsZero() && !time.Now().Before(id.ExpireTime) {
			break
		}
		return pdp.Subject{UserID: id.UserID, Status: pdp.Status(id.Status)}
	}
	return pdp.Subject{Status: pdp.StatusUnlinked}
}

type socketSessionResponse struct {
	Schema string `json:"schema"`
	UserID string `json:"user_id"`
	Status string `json:"status"`
}

func (l *LocalPDP) handleSessionGet(w http.ResponseWriter, r *http.Request) {
	subject, ok := l.Sessions.Current()
	if !ok {
		writeRuntimeError(w, http.StatusNotFound, "no_session", "no active session")
		return
	}
	resp := socketSessionResponse{
		Schema: sessionSchema,
		UserID: subject.UserID,
		Status: string(subject.Status),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (l *LocalPDP) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	var req socketAuthorizeRequest
	if err := decodeSocketJSON(w, r, &req); err != nil || req.Schema != authorizeRequestSchema {
		writeRuntimeError(w, http.StatusBadRequest, "invalid_request", "request must be a "+authorizeRequestSchema+" object with no unknown fields")
		return
	}
	if (req.Tool == "") == (req.Connector == nil) || (req.Connector != nil && (req.Connector.ConnectorID == "" || req.Connector.Capability == "")) {
		writeRuntimeError(w, http.StatusBadRequest, "invalid_request", "request needs exactly one of tool or connector{connector_id, capability}")
		return
	}
	preq := pdp.Request{Tool: req.Tool, Action: req.Action, Resource: req.Resource, AgentID: req.AgentID}
	if req.Connector != nil {
		preq.Connector = &pdp.ConnectorTarget{ConnectorID: req.Connector.ConnectorID, Capability: req.Connector.Capability}
	}
	d := pdp.Decision{ReasonCode: "policy_bundle_missing", DenySource: "runtime_state", Reason: "runtime identity is not resolved yet", BundleState: "cold"}
	if e := l.evaluator.Load(); e != nil {
		var err error
		if d, err = e.Evaluate(r.Context(), preq); err != nil {
			writeRuntimeError(w, http.StatusServiceUnavailable, "request_canceled", "request canceled")
			return
		}
	}
	resp := socketAuthorizeResponse{Schema: authorizeResponseSchema, Decision: "deny", ReasonCode: d.ReasonCode, DenySource: d.DenySource, Reason: d.Reason, PolicyID: d.PolicyID, BundleState: d.BundleState, Enrollment: d.Enrollment}
	if d.Allow {
		resp.Decision = policybundle.DecisionPermit
	}
	if d.BundleVersion > 0 {
		resp.PolicyBundleVersion, resp.PolicyBundleDigest, resp.PolicyRevision = &d.BundleVersion, d.BundleDigest, &d.PolicyRevision
	}
	if l.emit != nil {
		data := l.decisionEventJSON(req, d)
		l.emit(data)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (l *LocalPDP) decisionEventJSON(req socketAuthorizeRequest, d pdp.Decision) json.RawMessage {
	spanID := req.SpanID
	if spanID == "" {
		spanID = uuid.NewString()
	}
	toolName := req.Tool
	if req.Connector != nil {
		toolName = "connector:" + req.Connector.ConnectorID + "/" + req.Connector.Capability
	}
	e := socketDecisionEvent{
		SpanID: spanID, InvokedAt: time.Now().UTC().Format(time.RFC3339Nano), DelegationDepth: req.DelegationDepth,
		AgentID: req.AgentID, Framework: req.Framework, ToolName: toolName, ResourcesTouched: []string{},
		Decision: "deny", BundleState: d.BundleState, DenySource: d.DenySource, ReasonCode: d.ReasonCode,
	}
	if d.Allow {
		e.Decision = "allow"
	}
	if subject, ok := l.Sessions.Current(); ok {
		e.InvokingSubject = subject.UserID
	}
	if req.Resource != "" {
		e.ResourcesTouched = []string{req.Resource}
	}
	if req.ParentSpan != "" {
		e.ParentSpan = &req.ParentSpan
	}
	if req.ToolArgsDigest != "" {
		e.ToolArgsDigest = &req.ToolArgsDigest
	}
	if d.PolicyID != "" {
		e.PolicyID = &d.PolicyID
	}
	if d.Reason != "" {
		e.PolicyReason = &d.Reason
	}
	if d.BundleVersion > 0 {
		e.PolicyBundleVersion, e.PolicyBundleDigest, e.PolicyRevision = &d.BundleVersion, d.BundleDigest, &d.PolicyRevision
	}
	if id := l.identity.Load(); id != nil {
		e.OrgID, e.WorkspaceID = &id.OrgID, id.WorkspaceID
	}
	data, _ := json.Marshal(e)
	return data
}

func decodeSocketJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSocketRequest))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

func writeRuntimeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"message": message, "type": "runtime_error", "code": code},
	})
}
