package runtime

// POST /v1/session:subjectToken: opt-in export of a bound service principal's
// subject token to a caller holding that principal's session on the
// owner-only socket (owner decision 2026-11-01). The token is a bearer valid
// for up to ~8 h, so every guard fails closed.

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/session"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
)

const (
	subjectTokenPath           = "/v1/session:subjectToken"
	subjectTokenResponseSchema = "kei.subject-token/v1"
	// subjectTokenAuditTool names the governed event in audit records.
	subjectTokenAuditTool = "kei:session.subjectToken"
	// minSubjectTokenLifetime is the least time a token must have left to be
	// exported. A shorter one is refused; the bundle refresh replaces it.
	minSubjectTokenLifetime = 60 * time.Second
)

// Reason codes of the subject-token route. Bundle-state refusals reuse the
// runtime_state codes of a decision (policy_bundle_expired,
// subject_snapshot_stale, ...).
const (
	reasonSubjectTokenExportDisabled = "subject_token_export_disabled"
	reasonPrincipalSessionRequired   = "principal_session_required"
	reasonPrincipalNotExportable     = "service_principal_not_exportable"
	reasonPrincipalUnavailable       = "service_principal_unavailable"
	reasonSubjectTokenExpiring       = "subject_token_expiring"
	reasonRuntimeIdentityUnavailable = "runtime_identity_unavailable"
)

type socketSubjectTokenResponse struct {
	Schema             string `json:"schema"`
	SubjectToken       string `json:"subject_token"`
	ExpireTime         string `json:"expire_time"`
	ServicePrincipalID string `json:"service_principal_id"`
}

// exportablePrincipals is the KEI_EXPORTABLE_SERVICE_PRINCIPALS allow-list of
// principal names. Empty means the route refuses every request.
type exportablePrincipals struct {
	names atomic.Pointer[map[string]struct{}]
}

func (p *exportablePrincipals) set(names []string) {
	m := make(map[string]struct{}, len(names))
	for _, name := range names {
		if name = strings.TrimSpace(name); name != "" {
			m[name] = struct{}{}
		}
	}
	p.names.Store(&m)
}

func (p *exportablePrincipals) empty() bool {
	m := p.names.Load()
	return m == nil || len(*m) == 0
}

func (p *exportablePrincipals) allows(name string) bool {
	m := p.names.Load()
	if m == nil || name == "" {
		return false
	}
	_, ok := (*m)[name]
	return ok
}

// SetExportableServicePrincipals sets the principal names whose subject token
// POST /v1/session:subjectToken may return (KEI_EXPORTABLE_SERVICE_PRINCIPALS).
// Nil or empty turns the route off: every request is refused.
func (l *LocalPDP) SetExportableServicePrincipals(names []string) { l.exportable.set(names) }

// subjectTokenRefusal is one failed guard.
type subjectTokenRefusal struct {
	status     int
	code       string
	message    string
	denySource string
	state      string
}

// handleSubjectToken serves POST /v1/session:subjectToken. The caller has
// already passed runtime-token authentication. The token always comes from
// the current verified bundle, never from the caller or the session, and is
// never logged or written to audit.
func (l *LocalPDP) handleSubjectToken(w http.ResponseWriter, r *http.Request) {
	sessionID := session.FromRequest(r)
	principalID := ""
	refuse := func(f subjectTokenRefusal) {
		l.emitSubjectTokenEvent(sessionID, principalID, "deny", f.code, f.denySource, f.message, f.state)
		writeRuntimeError(w, f.status, f.code, f.message)
	}
	if l.exportable.empty() {
		refuse(subjectTokenRefusal{http.StatusForbidden, reasonSubjectTokenExportDisabled, "subject token export is disabled; set KEI_EXPORTABLE_SERVICE_PRINCIPALS to enable it", "runtime_state", ""})
		return
	}
	if !emptyJSONBody(w, r) {
		writeRuntimeError(w, http.StatusBadRequest, "invalid_request", "request body must be empty or {}")
		return
	}
	sub, ok := l.Sessions.Get(sessionID)
	if sessionID == pdp.DefaultSession || !ok {
		refuse(subjectTokenRefusal{http.StatusNotFound, string(pdp.ReasonSessionNotFound), "the session does not exist or has ended", "identity", ""})
		return
	}
	if sub.SubjectKind != "service_principal" || sub.Status != pdp.StatusLinked || sub.UserID == "" {
		refuse(subjectTokenRefusal{http.StatusForbidden, reasonPrincipalSessionRequired, "subject token export requires a live service-principal session", "identity", ""})
		return
	}
	principalID = sub.UserID
	identity, e := l.identity.Load(), l.evaluator.Load()
	if identity == nil || identity.AgentID == "" || e == nil {
		refuse(subjectTokenRefusal{http.StatusServiceUnavailable, reasonRuntimeIdentityUnavailable, "the trusted agent identity is unavailable", "runtime_state", "cold"})
		return
	}
	if d, inactive := e.InactiveBundleDenial(); inactive {
		refuse(subjectTokenRefusal{http.StatusServiceUnavailable, string(d.ReasonCode), "the policy bundle is not active: " + d.Reason, d.DenySource, d.BundleState})
		return
	}
	principal, ok := e.BundleServicePrincipalIdentity(principalID, identity.AgentID)
	if !ok {
		refuse(subjectTokenRefusal{http.StatusForbidden, reasonPrincipalUnavailable, "the service principal is no longer bound to this agent in the current bundle", "identity", "ready"})
		return
	}
	if !l.exportable.allows(principal.ServicePrincipalName) {
		refuse(subjectTokenRefusal{http.StatusForbidden, reasonPrincipalNotExportable, "the service principal is not in KEI_EXPORTABLE_SERVICE_PRINCIPALS", "policy", "ready"})
		return
	}
	if principal.SubjectToken == "" || time.Until(principal.ExpireTime) < minSubjectTokenLifetime {
		refuse(subjectTokenRefusal{http.StatusServiceUnavailable, reasonSubjectTokenExpiring, "the subject token is missing or expires within 60s; retry after the next bundle refresh", "runtime_state", "ready"})
		return
	}
	expire := principal.ExpireTime.UTC().Format(time.RFC3339)
	l.emitSubjectTokenEvent(sessionID, principalID, "allow", "", "", "subject token issued; expire_time="+expire, "ready")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(socketSubjectTokenResponse{
		Schema: subjectTokenResponseSchema, SubjectToken: principal.SubjectToken,
		ExpireTime: expire, ServicePrincipalID: principal.ServicePrincipalID,
	})
}

// emptyJSONBody reports whether the body is empty or the empty JSON object.
func emptyJSONBody(w http.ResponseWriter, r *http.Request) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxSocketRequest))
	if err != nil {
		return false
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return true
	}
	var fields map[string]json.RawMessage
	return json.Unmarshal(body, &fields) == nil && fields != nil && len(fields) == 0
}

// emitSubjectTokenEvent writes one decision audit record for a subject-token
// request. It uses only the existing decision-record fields (the catalog's
// audit:flush rejects unknown ones), so expire_time travels in policy_reason.
// The token itself is never passed here.
func (l *LocalPDP) emitSubjectTokenEvent(sessionID, principalID, decision, reasonCode, denySource, reason, bundleState string) {
	if l.emit == nil {
		return
	}
	e := socketDecisionEvent{
		SpanID: uuid.NewString(), InvokedAt: time.Now().UTC().Format(time.RFC3339Nano),
		AgentID: l.trustedAgentID(), ToolName: subjectTokenAuditTool, ResourcesTouched: []string{},
		Decision: decision, DenySource: denySource, ReasonCode: reasonCode, BundleState: bundleState,
		InvokingSubject: UnauthenticatedSubject,
	}
	if principalID != "" {
		e.InvokingSubject = "service_principal:" + principalID
		e.ResourcesTouched = []string{"service_principal:" + principalID}
	}
	if sessionID != pdp.DefaultSession {
		e.SessionID = &sessionID
	}
	if reason != "" {
		e.PolicyReason = &reason
	}
	if id := l.identity.Load(); id != nil {
		e.OrgID, e.WorkspaceID = &id.OrgID, id.WorkspaceID
	}
	data, _ := json.Marshal(e)
	l.emit(data)
}
