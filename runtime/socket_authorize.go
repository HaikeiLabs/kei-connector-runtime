package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/credrelease"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/session"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/denyhint"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

const (
	authorizeRequestSchema  = "kei.authorize-request/v1"
	authorizeResponseSchema = "kei.authorize-response/v1"
	// credentialReleaseRequestSchema/ResponseSchema are the HAI-722
	// pass-through route (kei-connector-contracts docs/credential-passthrough.md).
	credentialReleaseRequestSchema  = "kei.credential-release-request/v1"
	credentialReleaseResponseSchema = "kei.credential-release-response/v1"
	sessionSchema                   = "kei.session/v1"
	// sessionSchemaV2 creates a named session (multi-session socket API).
	sessionSchemaV2      = "kei.session/v2"
	bundleStatusSchema   = "kei.policy-bundle-status/v1"
	maxSocketRequest     = 64 << 10
	maxSocketPlanRequest = 192 << 10
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
	OnBehalfOf      string                    `json:"on_behalf_of,omitempty"`
	// ShellCommand is accepted only over the tenant-local socket and is used
	// solely to evaluate shell: policies. It is never copied to audit events.
	ShellCommand string `json:"shell_command,omitempty"`
}

type socketAuthorizeConnector struct {
	ConnectorID string `json:"connector_id"`
	Capability  string `json:"capability"`
}

type socketAuthorizeResponse struct {
	Schema              string          `json:"schema"`
	Decision            string          `json:"decision"` // permit | deny | unmatched
	ReasonCode          string          `json:"reason_code,omitempty"`
	Hint                string          `json:"hint,omitempty"`
	DenySource          string          `json:"deny_source,omitempty"`
	Reason              string          `json:"reason,omitempty"`
	PolicyID            string          `json:"policy_id,omitempty"`
	PolicyBundleVersion *int64          `json:"policy_bundle_version,omitempty"`
	PolicyBundleDigest  string          `json:"policy_bundle_digest,omitempty"`
	PolicyRevision      *int64          `json:"policy_revision,omitempty"`
	BundleState         string          `json:"bundle_state"`
	Enrollment          json.RawMessage `json:"enrollment,omitempty"`
}

// socketCredentialReleaseResponse is the HAI-722 pass-through answer. On
// allow it carries the connector credential value + expiry and the policy
// metadata; on a policy deny or a missing/expired credential it carries a
// typed reason_code and no credential (never a fallback).
type socketCredentialReleaseResponse struct {
	Schema              string                       `json:"schema"`
	Decision            string                       `json:"decision"`
	ReasonCode          string                       `json:"reason_code,omitempty"`
	Reason              string                       `json:"reason,omitempty"`
	Credential          *socketCredentialReleaseCred `json:"credential,omitempty"`
	PolicyID            string                       `json:"policy_id,omitempty"`
	PolicyBundleVersion *int64                       `json:"policy_bundle_version,omitempty"`
	PolicyBundleDigest  string                       `json:"policy_bundle_digest,omitempty"`
	PolicyRevision      *int64                       `json:"policy_revision,omitempty"`
	BundleState         string                       `json:"bundle_state"`
}

type socketCredentialReleaseCred struct {
	ConnectorID  string `json:"connector_id"`
	Issuer       string `json:"issuer"`
	Resource     string `json:"resource"`
	AccountModel string `json:"account_model"`
	AccessToken  string `json:"access_token"`
	ExpiresAt    string `json:"expires_at"`
}

type socketSessionRequest struct {
	Schema               string          `json:"schema"`
	ServicePrincipalID   string          `json:"service_principal_id,omitempty"`
	ServicePrincipalName string          `json:"service_principal_name,omitempty"`
	UserID               string          `json:"user_id,omitempty"`
	Email                string          `json:"email,omitempty"`
	Status               string          `json:"status"`
	Enrollment           json.RawMessage `json:"enrollment,omitempty"`
	Source               string          `json:"source,omitempty"`
	ExternalID           string          `json:"external_id,omitempty"`
}

type EmitAuditFunc func(json.RawMessage)

// ToolRegistrar syncs a validated tool manifest to the catalog using the
// runtime installation credential and returns the catalog's sync counts.
type ToolRegistrar interface {
	RegisterTools(context.Context, string, *ToolManifest) (*ToolSyncResponse, error)
}

type runtimeToolRegistrar struct{ client *runtimeClient }

func (r runtimeToolRegistrar) RegisterTools(ctx context.Context, token string, manifest *ToolManifest) (*ToolSyncResponse, error) {
	return r.client.SyncToolsWithResponse(ctx, token, manifest)
}

type socketDecisionEvent struct {
	SpanID              string   `json:"span_id"`
	InvokedAt           string   `json:"invoked_at"`
	DelegationDepth     int      `json:"delegation_depth"`
	AgentID             string   `json:"agent_id"`
	Framework           string   `json:"framework"`
	ToolName            string   `json:"tool_name"`
	InvokingSubject     string   `json:"invoking_subject"`
	OnBehalfOf          string   `json:"on_behalf_of,omitempty"`
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
	SessionID           *string  `json:"session_id,omitempty"`
	// CredentialReleased is set only by the HAI-722 pass-through route: true
	// when a credential value crossed the socket. The value itself is never
	// recorded.
	CredentialReleased *bool `json:"credential_released,omitempty"`
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

	// creds creates per-session credential stores held in sessionCreds.
	creds              *credrelease.Store
	sessionCreds       sync.Map
	runner             http.Handler
	toolRegistrar      ToolRegistrar
	modelConfigHandler http.Handler
	stopSweep             chan struct{}
	closeOnce             sync.Once
	ownerMu               sync.RWMutex
	ownerID               string
	tokenlessOwnerSession bool
	ownerUnavailable      bool
	// endHooks run after a named session's credentials are dropped.
	endHooksMu sync.Mutex
	endHooks   []func(id string)
}

func NewLocalPDP(cfg PolicyConfig, emit EmitAuditFunc) *LocalPDP {
	l := &LocalPDP{cfg: cfg, Sessions: pdp.NewSessions(), emit: emit, stopSweep: make(chan struct{})}
	if cfg != nil && cfg.ControlPlaneURL() != "" {
		l.toolRegistrar = runtimeToolRegistrar{client: &runtimeClient{baseURL: strings.TrimRight(cfg.ControlPlaneURL(), "/"), client: &http.Client{Timeout: 15 * time.Second}}}
	}
	// A named session's credentials go with it, however it ends.
	l.Sessions.OnEnd(l.sessionEnded)
	// A session recycled by max-age also emits a lifecycle event.
	l.Sessions.OnRecycle(func(id string) {
		_ = AppendLifecycleEvent(cfg.PolicyAuditPath(), cfg.PolicyAuditMaxBytes(), LifecycleEvent{
			EventType:  "session_recycled",
			ObservedAt: time.Now().UTC(),
			Attrs:      map[string]string{"session_id": id},
		})
	})
	return l
}

// SetSessionIdleTTL sets how long a named session lives without use
// (KEI_SESSION_IDLE_TTL). The default session never expires.
func (l *LocalPDP) SetSessionIdleTTL(d time.Duration) { l.Sessions.SetIdleTTL(d) }

// SetSessionNow replaces the session time source (for tests). A nil fn
// panics on use.
func (l *LocalPDP) SetSessionNow(fn func() time.Time) { l.Sessions.SetNow(fn) }

// SetTokenlessOwnerSession controls tokenless access on the owner-only socket.
func (l *LocalPDP) SetTokenlessOwnerSession(enabled bool) {
	l.ownerMu.Lock()
	l.tokenlessOwnerSession = enabled
	if enabled && l.ownerID == "" {
		l.ownerUnavailable = true
	}
	if !enabled {
		l.endOwnerSessionLocked()
		l.ownerUnavailable = false
	}
	l.ownerMu.Unlock()
}

func (l *LocalPDP) reconcileOwnerSession() {
	l.ownerMu.Lock()
	if !l.tokenlessOwnerSession {
		l.ownerMu.Unlock()
		return
	}
	e := l.evaluator.Load()
	if e == nil {
		l.endOwnerSessionLocked()
		l.ownerUnavailable = true
		l.ownerMu.Unlock()
		return
	}
	bundleSubject, ok := e.BundleInstallationSubject()
	if !ok {
		l.endOwnerSessionLocked()
		l.ownerUnavailable = true
		l.ownerMu.Unlock()
		return
	}
	// Recreate on every successful refresh so email/groups never outlive the
	// currently verified installation subject.
	l.endOwnerSessionLocked()
	// The owner session's policy principal comes from the installation subject.
	// Credential release, when enabled, still requires user evidence: reuse a
	// matching linked identity's subject token from this fresh verified bundle.
	// Never infer credentials from the installation token or from a caller.
	sub := pdp.Subject{UserID: bundleSubject.UserID, Email: bundleSubject.Email, Groups: bundleSubject.Groups, Status: pdp.StatusLinked, Source: "installation_owner", ExternalID: bundleSubject.UserID}
	if linked, ok := e.LookupLinkedUser(bundleSubject.UserID); ok {
		sub.Token = linked.SubjectToken
	}
	id, err := l.Sessions.CreatePinned(sub)
	if err != nil {
		l.ownerUnavailable = true
		l.ownerMu.Unlock()
		return
	}
	l.ownerID = id
	l.ownerUnavailable = false
	if l.creds != nil {
		l.sessionCreds.Store(id, l.creds.NewSession())
		if !l.Sessions.Exists(id) {
			l.dropSessionCredentials(id)
			l.ownerID = ""
			l.ownerUnavailable = true
			l.ownerMu.Unlock()
			return
		}
	}
	l.ownerMu.Unlock()
	if l.creds != nil {
		// Don't hold the socket-binding lock during the bounded I11 request.
		// A concurrent bundle refresh ends this session and flushes a late load.
		l.loadCredentials(context.Background(), id, sub)
	}
}

func (l *LocalPDP) endOwnerSessionLocked() {
	if l.ownerID != "" {
		l.Sessions.EndID(l.ownerID)
		l.ownerID = ""
	}
}

// SweepSessions ends idle named sessions until ctx is done or Close. The
// serve daemon runs it; idle sessions also end when next used.
func (l *LocalPDP) SweepSessions(ctx context.Context) {
	every := min(l.Sessions.IdleTTL()/2, time.Minute)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-l.stopSweep:
			return
		case <-t.C:
			if ended := l.Sessions.Sweep(); len(ended) > 0 {
				slog.Info("sessions_expired", "count", len(ended))
			}
		}
	}
}

// idleTTLSeconds is the idle TTL in whole seconds, rounded up so it is
// never reported as zero.
func (l *LocalPDP) idleTTLSeconds() int64 {
	return int64((l.Sessions.IdleTTL() + time.Second - 1) / time.Second)
}

func (l *LocalPDP) SetKeychain(k SessionKeychain) { l.keychain = k }

// SetCredentialStore turns on session credential release
// (KEI_CREDENTIAL_RELEASE=identity): linked named sessions and the tokenless
// owner session fetch credentials only from subject tokens in verified bundle
// identities. Each session has its own store and every session end flushes it.
// Without a store (legacy) sessions hold no credentials.
func (l *LocalPDP) SetCredentialStore(store *credrelease.Store) { l.creds = store }

// errCredentialReleaseOff is returned by UseCredential in legacy mode.
var errCredentialReleaseOff = errors.New("session credential release is not enabled")
var errCredentialAccountModelUnsupported = errors.New("tool-bound credential release requires a shared account model")
var errCredentialAudienceMismatch = errors.New("tool-bound credential does not match its requested audience")

// UseCredential runs fn with the credential for provider held by session id
// (DefaultSession for the legacy default session) for subject (a user id),
// inside the daemon (ADR-034 option A). It is the only way to reach a held
// credential; no socket route returns one, and a session can reach only its
// own. See credrelease.Store.Use.
func (l *LocalPDP) UseCredential(ctx context.Context, id, subject, provider string, fn func(token string) error) error {
	if l.creds == nil {
		return errCredentialReleaseOff
	}
	store := l.credentialStore(id)
	if store == nil {
		return &credrelease.DeniedError{Provider: provider, Reason: credrelease.ReasonNoSession}
	}
	return store.Use(ctx, subject, provider, fn)
}

// UseConnectorCredential runs fn with the credential session id holds for
// subject, one connector and one resource (HAI-577, ADR-036 §4.8). fn's error
// is returned unchanged.
func (l *LocalPDP) UseConnectorCredential(ctx context.Context, id, subject, connectorID, resource string, fn func(credrelease.ConnectorCredential) error) error {
	if l.creds == nil {
		return errCredentialReleaseOff
	}
	store := l.credentialStore(id)
	if store == nil {
		return &credrelease.DeniedError{Provider: connectorID, Reason: credrelease.ReasonNoSession}
	}
	return store.UseConnector(ctx, subject, connectorID, resource, fn)
}

// DropConnectorCredential forgets session id's credential for one connector
// and resource after the upstream rejected it.
func (l *LocalPDP) DropConnectorCredential(id, connectorID, resource string) {
	if store := l.credentialStore(id); store != nil {
		store.DropConnector(connectorID, resource)
	}
}

// credentialStore is session id's credential store, or nil.
func (l *LocalPDP) credentialStore(id string) *credrelease.Store {
	if id == pdp.DefaultSession {
		return nil
	}
	if v, ok := l.sessionCreds.Load(id); ok {
		return v.(*credrelease.Store)
	}
	return nil
}

// flushSession zeroes session id's credentials; a named session's store is
// also dropped.
func (l *LocalPDP) flushSession(id string) {
	l.dropSessionCredentials(id)
}

func (l *LocalPDP) dropSessionCredentials(id string) {
	if v, ok := l.sessionCreds.LoadAndDelete(id); ok {
		v.(*credrelease.Store).Flush()
	}
}

// OnSessionEnd registers fn to run, once per named session, when the session
// ends for any reason, after its credentials are dropped. fn runs on the
// ending goroutine and must not block.
func (l *LocalPDP) OnSessionEnd(fn func(id string)) {
	l.endHooksMu.Lock()
	defer l.endHooksMu.Unlock()
	l.endHooks = append(l.endHooks, fn)
}

func (l *LocalPDP) sessionEnded(id string) {
	l.dropSessionCredentials(id)
	l.endHooksMu.Lock()
	hooks := append([]func(string){}, l.endHooks...)
	l.endHooksMu.Unlock()
	for _, fn := range hooks {
		fn(id)
	}
}

// SetCommandRunner serves POST /v1/commands:run with h (HAI-346 L3c): native
// CLI tools for Unix/local-process harnesses (Claude Code, Codex, opencode via
// `kei-proxy run -- <cmd>`), spawned by this daemon with the session-held
// credentials injected only into the child's environment, behind the
// socket's config and runtime-token checks. Without one the route is not
// served.
func (l *LocalPDP) SetCommandRunner(h http.Handler) { l.runner = h }

// SetToolRegistrar configures POST /v1/tools:register. Without a registrar,
// the route remains fail closed and reports that tool registration is unavailable.
func (l *LocalPDP) SetToolRegistrar(registrar ToolRegistrar) { l.toolRegistrar = registrar }

// SetModelConfigHandler serves GET /v1/model-config with h (HAI-671):
// returns the runtime's assigned model profile as a config source (model,
// endpoint, credential) for the harness. Without one the route is not served.
func (l *LocalPDP) SetModelConfigHandler(h http.Handler) { l.modelConfigHandler = h }

// AuthorizeConnector decides a connector call with the local PDP and the
// session subject, and returns the runtime identity it was decided under.
// Before the identity resolves, every call denies policy_bundle_missing. The
// error is non-nil only when ctx is done.
func (l *LocalPDP) AuthorizeConnector(ctx context.Context, req pdp.Request) (pdp.ConnectorGrant, *Identity, error) {
	e, id := l.evaluator.Load(), l.identity.Load()
	if e == nil || id == nil {
		if req.Session != pdp.DefaultSession && !l.Sessions.Exists(req.Session) {
			return pdp.ConnectorGrant{Decision: pdp.Decision{ReasonCode: pdp.ReasonSessionNotFound, DenySource: "identity", Reason: "the session does not exist or has ended"}}, nil, ctx.Err()
		}
		g := pdp.ConnectorGrant{Decision: pdp.Decision{ReasonCode: "policy_bundle_missing", DenySource: "runtime_state", Reason: "runtime identity is not resolved yet", BundleState: "cold"}}
		if sub, ok := l.Sessions.Get(req.Session); ok {
			sub.Token, sub.Enrollment = "", nil
			g.Subject, g.HasSession = sub, true
		}
		return g, nil, ctx.Err()
	}
	g, err := e.EvaluateConnector(ctx, req)
	return g, id, err
}

// AuditScope returns the installation's org, workspace and installation ids
// for audit records ("" before the identity resolves).
func (l *LocalPDP) AuditScope() (orgID, workspaceID, installationID string) {
	id := l.identity.Load()
	if id == nil {
		return "", "", ""
	}
	if id.WorkspaceID != nil {
		workspaceID = *id.WorkspaceID
	}
	return id.OrgID, workspaceID, id.ID
}

// Close stops the session sweeper and flushes every held session
// credential. The serve daemon calls it on exit.
func (l *LocalPDP) Close() {
	l.closeOnce.Do(func() { close(l.stopSweep) })
	l.flushCredentials()
}

// flushCredentials flushes every session's credentials.
func (l *LocalPDP) flushCredentials() {
	if l.creds != nil {
		l.creds.Flush()
	}
	l.sessionCreds.Range(func(k, _ any) bool {
		l.dropSessionCredentials(k.(string))
		return true
	})
}

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
		l.ownerMu.Lock()
		l.endOwnerSessionLocked()
		l.ownerUnavailable = l.tokenlessOwnerSession
		l.ownerMu.Unlock()
		if e != nil {
			e.RevokeSession()
		} else {
			l.Sessions.End()
			l.Sessions.RevokeAll()
		}
		l.flushCredentials()
		return
	}
	if e == nil {
		l.ownerMu.Lock()
		l.endOwnerSessionLocked()
		l.ownerUnavailable = l.tokenlessOwnerSession
		l.ownerMu.Unlock()
	}
	if e != nil {
		// Refresh/revocation is the freshness boundary for the owner session.
		l.reconcileOwnerSession()
		// Each session is reconciled on its own; only revoked ones flush.
		for _, id := range e.ReconcileSessions() {
			l.flushSession(id)
		}
	}
	if sub, ok := l.Sessions.Current(); !ok || sub.Status != pdp.StatusLinked {
		l.flushSession(pdp.DefaultSession)
	}
}

func (l *LocalPDP) NewHandler(next http.Handler, checkConfig func() error, checkAuth func(*http.Request) bool) http.Handler {
	return l.newHandler(next, checkConfig, checkAuth, false)
}

// NewSocketHandler is for the owner-only Unix socket listener only. It allows
// unauthenticated POST /v1/authorize requests, but never exposes enrollment
// claim URLs to callers that did not authenticate with the runtime token.
func (l *LocalPDP) NewSocketHandler(next http.Handler, checkConfig func() error, checkAuth func(*http.Request) bool) http.Handler {
	return l.newHandler(next, checkConfig, checkAuth, true)
}

func (l *LocalPDP) newHandler(next http.Handler, checkConfig func() error, checkAuth func(*http.Request) bool, allowUnauthenticatedAuthorize bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/authorize" && r.Method == http.MethodPost:
		case r.URL.Path == "/v1/session" && (r.Method == http.MethodPut || r.Method == http.MethodDelete || r.Method == http.MethodGet):
		case r.URL.Path == "/v1/policy-bundle/status" && r.Method == http.MethodGet:
		case r.URL.Path == "/v1/commands:run" && r.Method == http.MethodPost && l.runner != nil:
		case r.URL.Path == "/v1/credentials:release" && r.Method == http.MethodPost && l.creds != nil:
		case r.URL.Path == "/v1/tools:register" && r.Method == http.MethodPost:
		case r.URL.Path == "/v1/model-config" && r.Method == http.MethodGet && l.modelConfigHandler != nil:
		default:
			next.ServeHTTP(w, r)
			return
		}
		if err := checkConfig(); err != nil {
			writeRuntimeError(w, http.StatusServiceUnavailable, "runtime_not_configured", err.Error())
			return
		}
		authenticated := checkAuth(r)
		routeAllowsOwner := r.Method == http.MethodPost && (r.URL.Path == "/v1/authorize" || r.URL.Path == "/v1/credentials:release")
		l.ownerMu.RLock()
		ownerID, ownerEnabled, ownerUnavailable := l.ownerID, l.tokenlessOwnerSession, l.ownerUnavailable
		l.ownerMu.RUnlock()
		unauthenticatedOwner := allowUnauthenticatedAuthorize && routeAllowsOwner && ownerEnabled && ownerID != "" && !authenticated && session.FromRequest(r) == pdp.DefaultSession
		if !authenticated && !unauthenticatedOwner && !(allowUnauthenticatedAuthorize && ownerEnabled && routeAllowsOwner && !authenticated && ownerUnavailable) {
			writeRuntimeError(w, http.StatusUnauthorized, "invalid_runtime_token", "runtime authentication failed")
			return
		}
		if unauthenticatedOwner {
			r = r.Clone(r.Context())
			r.Header = r.Header.Clone()
			session.SetHeader(r, ownerID)
		} else if !authenticated && ownerUnavailable {
			writeRuntimeError(w, http.StatusForbidden, "owner_subject_unavailable", "the installation owner subject is unavailable in the current v2 bundle")
			return
		}
		switch {
		case r.URL.Path == "/v1/authorize":
			l.handleAuthorize(w, r, authenticated)
		case r.URL.Path == "/v1/policy-bundle/status":
			l.handlePolicyBundleStatus(w)
		// The credentialed route runs inside this serve daemon with the
		// session-held credentials, which never leave it: commands:run spawns
		// native CLI tools (gh, git, ...) for Unix/local-process harnesses
		// such as Claude Code, Codex and opencode, via `kei-proxy run -- <cmd>`.
		case r.URL.Path == "/v1/commands:run":
			l.runner.ServeHTTP(w, r)
		case r.URL.Path == "/v1/tools:register":
			l.handleToolRegistration(w, r)
		case r.URL.Path == "/v1/credentials:release":
			l.handleCredentialRelease(w, r)
		case r.URL.Path == "/v1/model-config":
			l.modelConfigHandler.ServeHTTP(w, r)
		case r.Method == http.MethodPut:
			l.handleSessionStart(w, r)
		case r.Method == http.MethodGet:
			l.handleSessionGet(w, r)
		default:
			l.handleSessionEnd(w, r)
		}
	})
}

// handleSessionEnd serves DELETE /v1/session: it ends the named session (or
// the default one) and flushes only that session's credentials.
func (l *LocalPDP) handleSessionEnd(w http.ResponseWriter, r *http.Request) {
	id := session.FromRequest(r)
	if !l.Sessions.EndID(id) {
		writeRuntimeError(w, http.StatusNotFound, pdp.ReasonSessionNotFound, "the session does not exist or has ended")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (l *LocalPDP) handleToolRegistration(w http.ResponseWriter, r *http.Request) {
	if l.cfg == nil || l.cfg.Token() == "" {
		writeRuntimeError(w, http.StatusServiceUnavailable, "runtime_credentials_unavailable", "runtime credentials are unavailable")
		return
	}
	if l.toolRegistrar == nil {
		writeRuntimeError(w, http.StatusServiceUnavailable, "tool_registration_unavailable", "tool registration is unavailable")
		return
	}
	var manifest ToolManifest
	if err := decodeSocketJSONLimit(w, r, &manifest, maxSocketPlanRequest); err != nil {
		writeRuntimeError(w, http.StatusBadRequest, "invalid_manifest", "invalid tool manifest JSON")
		return
	}
	if manifest.Schema != ToolManifestSchemaV3 {
		writeRuntimeError(w, http.StatusBadRequest, "invalid_manifest", fmt.Sprintf("unsupported tool manifest schema: supported %s, received %q", ToolManifestSchemaV3, manifest.Schema))
		return
	}
	if len(manifest.Tools) == 0 {
		writeRuntimeError(w, http.StatusBadRequest, "invalid_manifest", "tool manifest must contain at least one tool")
		return
	}
	if err := validateToolManifest(&manifest); err != nil {
		writeRuntimeError(w, http.StatusBadRequest, "invalid_manifest", "invalid tool manifest: "+err.Error())
		return
	}
	result, err := l.toolRegistrar.RegisterTools(r.Context(), l.cfg.Token(), &manifest)
	if err != nil {
		var syncErr *ToolSyncError
		if errors.As(err, &syncErr) && syncErr.StatusCode == http.StatusBadRequest {
			writeRuntimeError(w, http.StatusBadRequest, "tool_sync_error", syncErr.Error())
			return
		}
		writeRuntimeError(w, http.StatusBadGateway, "tool_sync_error", err.Error())
		return
	}
	if result == nil {
		writeRuntimeError(w, http.StatusBadGateway, "tool_sync_error", "catalog returned no sync counts")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// handleSessionStart serves PUT /v1/session. A kei.session/v2 body creates a
// new named session and answers 201 with its id.
func (l *LocalPDP) handleSessionStart(w http.ResponseWriter, r *http.Request) {
	body, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, maxSocketRequest))
	if readErr != nil {
		writeRuntimeError(w, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	var req socketSessionRequest
	err := decodeSocketJSON(w, r, &req)
	if err != nil || req.Schema != sessionSchemaV2 {
		writeRuntimeError(w, http.StatusBadRequest, "invalid_request", "request must be a "+sessionSchemaV2+" object with no unknown fields")
		return
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(body, &fields)
	_, hasPrincipalID := fields["service_principal_id"]
	_, hasPrincipalName := fields["service_principal_name"]
	if hasPrincipalID || hasPrincipalName {
		if hasPrincipalID == hasPrincipalName || req.ServicePrincipalID == "" && req.ServicePrincipalName == "" {
			writeRuntimeError(w, http.StatusBadRequest, "invalid_session", "exactly one non-empty service-principal selector is required")
			return
		}
		for _, forbidden := range []string{"user_id", "email", "status", "source", "external_id", "enrollment", "groups", "subject_token", "agent_id"} {
			if _, supplied := fields[forbidden]; supplied {
				writeRuntimeError(w, http.StatusBadRequest, "invalid_session", "principal sessions do not accept caller-supplied identity fields")
				return
			}
		}
		if req.Schema != sessionSchemaV2 {
			writeRuntimeError(w, http.StatusBadRequest, "invalid_session", "service principals require a kei.session/v2 request")
			return
		}
		identity := l.identity.Load()
		e := l.evaluator.Load()
		if identity == nil || identity.AgentID == "" || e == nil {
			writeRuntimeError(w, http.StatusBadRequest, "invalid_session", "the trusted agent identity is unavailable")
			return
		}
		var principal policybundle.ServicePrincipalIdentity
		var ok bool
		if hasPrincipalID {
			principal, ok = e.BundleServicePrincipalIdentity(req.ServicePrincipalID, identity.AgentID)
		} else {
			principal, ok = e.BundleServicePrincipalIdentityByName(req.ServicePrincipalName, identity.AgentID)
		}
		if !ok {
			writeRuntimeError(w, http.StatusBadRequest, "invalid_session", "service principal is missing, disabled, expired, or not bound to this agent")
			return
		}
		sub := pdp.Subject{SubjectKind: "service_principal", UserID: principal.ServicePrincipalID, Groups: principal.Groups, Status: pdp.StatusLinked, Source: "cli", Token: principal.SubjectToken}
		id, err := l.Sessions.Create(sub)
		if err != nil {
			writeRuntimeError(w, http.StatusBadRequest, "invalid_session", err.Error())
			return
		}
		if l.creds != nil {
			l.sessionCreds.Store(id, l.creds.NewSession())
			if !l.Sessions.Exists(id) {
				l.dropSessionCredentials(id)
			}
		}
		l.loadCredentials(r.Context(), id, sub)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(socketSessionResponse{Schema: sessionSchemaV2, SessionID: id, ServicePrincipalID: principal.ServicePrincipalID, SubjectType: "service_principal", IdleTTLSeconds: l.idleTTLSeconds()})
		return
	}
	if req.UserID != "" || req.Email != "" || req.Status != "" || len(req.Enrollment) > 0 {
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
		sub = pdp.Subject{UserID: userID, Status: pdp.StatusLinked, Source: "cli", Token: token}
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
	id, err := l.Sessions.Create(sub)
	if err != nil {
		writeRuntimeError(w, http.StatusBadRequest, "invalid_session", err.Error())
		return
	}
	if l.creds != nil {
		l.sessionCreds.Store(id, l.creds.NewSession())
		if !l.Sessions.Exists(id) {
			// Ended before its store was attached: drop the orphan.
			l.dropSessionCredentials(id)
		}
	}
	l.loadCredentials(r.Context(), id, sub)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(socketSessionResponse{
		Schema: sessionSchemaV2, SessionID: id, UserID: sub.UserID, Status: string(sub.Status),
		IdleTTLSeconds: l.idleTTLSeconds(),
	})
}

// loadCredentials makes the session's one I11 call for a linked subject. A
// failure leaves the session without credentials (every use denies) but does
// not fail the session itself; only the error class and safe request metadata
// are logged.
func (l *LocalPDP) loadCredentials(ctx context.Context, id string, sub pdp.Subject) {
	store := l.credentialStore(id)
	if store == nil || sub.Status != pdp.StatusLinked || sub.Token == "" {
		return
	}
	if err := store.Load(ctx, sub.UserID, sub.Token); err != nil {
		attrs := []any{"error", err}
		if host, requestID, responseRequestID, ok := credrelease.RequestDiagnostics(err); ok {
			attrs = append(attrs, "credential_release_host", host, "credential_release_request_id", requestID)
			if responseRequestID != "" && responseRequestID != requestID {
				attrs = append(attrs, "credential_release_response_request_id", responseRequestID)
			}
		}
		slog.Warn("session_credentials_unavailable", attrs...)
		return
	}
	// A DELETE or another PUT that landed before Load began must still win.
	// A named session's end flushes its store, which discards this load.
}

// resolveBundleSubject looks up (source, external_id) in the evaluator's
// current bundle identities. When the identity is linked the returned subject
// carries the user id, linked status and subject token; otherwise it carries
// the identity's status (unlinked, pending, cross_workspace, revoked). An
// unknown or expired identity yields an unlinked subject.
func resolveBundleSubject(e *pdp.Evaluator, source, externalID string) pdp.Subject {
	id, ok := e.ResolveBundleIdentity(source, externalID)
	if !ok {
		return pdp.Subject{Status: pdp.StatusUnlinked}
	}
	sub := pdp.Subject{UserID: id.UserID, Status: pdp.Status(id.Status), Source: source, ExternalID: externalID}
	if sub.Status == pdp.StatusLinked {
		// The identity's ES256 subject token is the I11 subject evidence.
		sub.Token = id.SubjectToken
	}
	return sub
}

type socketSessionResponse struct {
	Schema             string `json:"schema"`
	SessionID          string `json:"session_id,omitempty"`
	UserID             string `json:"user_id,omitempty"`
	ServicePrincipalID string `json:"service_principal_id,omitempty"`
	SubjectType        string `json:"subject_type,omitempty"`
	Status             string `json:"status,omitempty"`
	IdleTTLSeconds     int64  `json:"idle_ttl_seconds,omitempty"`
}

func (l *LocalPDP) handleSessionGet(w http.ResponseWriter, r *http.Request) {
	id := session.FromRequest(r)
	subject, ok := l.Sessions.Get(id)
	if !ok {
		writeRuntimeError(w, http.StatusNotFound, pdp.ReasonSessionNotFound, "the session does not exist or has ended")
		return
	}
	resp := socketSessionResponse{Schema: sessionSchemaV2, SessionID: id, IdleTTLSeconds: l.idleTTLSeconds()}
	if subject.SubjectKind == "service_principal" {
		resp.ServicePrincipalID = subject.UserID
		resp.SubjectType = subject.SubjectKind
	} else {
		resp.UserID = subject.UserID
		resp.Status = string(subject.Status)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

type socketPolicyBundleStatus struct {
	Schema        string `json:"schema"`
	BundleSchema  string `json:"bundle_schema,omitempty"`
	BundleVersion int64  `json:"bundle_version,omitempty"`
	State         string `json:"state"`
}

// handlePolicyBundleStatus exposes only the locally stored bundle schema,
// version and state. It makes no control-plane call and returns no policy data.
func (l *LocalPDP) handlePolicyBundleStatus(w http.ResponseWriter) {
	result := socketPolicyBundleStatus{Schema: bundleStatusSchema, State: "cold"}
	if e := l.evaluator.Load(); e != nil {
		status, err := e.BundleStatus()
		result.State = string(status.State)
		if err == nil {
			result.BundleSchema, result.BundleVersion = status.BundleSchema, status.BundleVersion
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(result)
}

func (l *LocalPDP) handleAuthorize(w http.ResponseWriter, r *http.Request, includeEnrollment bool) {
	var req socketAuthorizeRequest
	if err := decodeSocketJSON(w, r, &req); err != nil || req.Schema != authorizeRequestSchema {
		writeRuntimeError(w, http.StatusBadRequest, "invalid_request", "request must be a "+authorizeRequestSchema+" object with no unknown fields")
		return
	}
	if (req.Tool == "") == (req.Connector == nil) || (req.Connector != nil && (req.Connector.ConnectorID == "" || req.Connector.Capability == "")) {
		writeRuntimeError(w, http.StatusBadRequest, "invalid_request", "request needs exactly one of tool or connector{connector_id, capability}")
		return
	}
	if !validOnBehalfOf(req.OnBehalfOf) {
		writeRuntimeError(w, http.StatusBadRequest, "invalid_request", "on_behalf_of must be empty or a type-prefixed value")
		return
	}
	sessionID := session.FromRequest(r)
	d, auditTrustedAgent, unmatched, err := l.decideAuthorize(r.Context(), sessionID, req)
	if err != nil {
		writeRuntimeError(w, http.StatusServiceUnavailable, "request_canceled", "request canceled")
		return
	}
	resp := socketAuthorizeResponseForDecision(d, includeEnrollment)
	if unmatched {
		resp.Decision = "unmatched"
	}
	if l.emit != nil {
		auditReq := req
		if auditTrustedAgent {
			// The request's AgentID is untrusted. Record the same assigned
			// default identity used for the policy decision.
			auditReq.AgentID = l.trustedAgentID()
		}
		data := l.decisionEventJSONWithUnmatched(auditReq, sessionID, d, nil, unmatched)
		l.emit(data)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// decideAuthorize computes the /v1/authorize decision for req in sessionID.
// It is shared by /v1/authorize and /v1/credentials:release so the two always
// agree. auditTrustedAgent is true when the decision used the runtime
// identity's default agent (the audit records that agent instead of the
// request's). The error is non-nil only when ctx is done.
func (l *LocalPDP) decideAuthorize(ctx context.Context, sessionID string, req socketAuthorizeRequest) (d pdp.Decision, auditTrustedAgent, unmatched bool, err error) {
	d = pdp.Decision{ReasonCode: "policy_bundle_missing", DenySource: "runtime_state", Reason: "runtime identity is not resolved yet", BundleState: "cold"}
	auditTrustedAgent = req.Tool == "shell"
	if sessionID == "" {
		d = pdp.Decision{ReasonCode: "session_required", DenySource: "identity", Reason: "a named session is required"}
		return d, auditTrustedAgent, false, nil
	}
	if !l.Sessions.Exists(sessionID) {
		d = pdp.Decision{ReasonCode: pdp.ReasonSessionNotFound, DenySource: "identity", Reason: "the session does not exist or has ended"}
		return d, auditTrustedAgent, false, nil
	}
	e := l.evaluator.Load()
	if e == nil {
		return d, auditTrustedAgent, false, nil
	}
	if sub, ok := l.Sessions.Get(sessionID); ok && sub.SubjectKind == "service_principal" {
		if _, valid := e.BundleServicePrincipalIdentity(sub.UserID, l.trustedAgentID()); !valid {
			return pdp.Decision{ReasonCode: "subject_unlinked", DenySource: "identity", Reason: "the principal is no longer present for this agent", BundleState: "ready"}, auditTrustedAgent, false, nil
		}
	}
	preq := pdp.Request{Session: sessionID, Tool: req.Tool, Action: req.Action, Resource: req.Resource, AgentID: req.AgentID}
	if req.Connector != nil {
		preq.Connector = &pdp.ConnectorTarget{ConnectorID: req.Connector.ConnectorID, Capability: req.Connector.Capability}
	}
	switch {
	// "shell" is the generic tool name for command authorization; adapters map their own shell tool to it.
	case req.Tool == "shell":
		if !validArgumentDigest(req.ToolArgsDigest) {
			d = pdp.Decision{ReasonCode: "invalid_tool_args_digest", DenySource: "policy", Reason: "shell authorization requires a SHA-256 argument digest"}
		} else if identity := l.identity.Load(); identity == nil || identity.AgentID == "" {
			d = pdp.Decision{ReasonCode: "agent_not_assigned", DenySource: "registry", Reason: "the trusted default agent is unavailable"}
		} else {
			// Never use the caller's optional AgentID; the authenticated
			// runtime identity supplies the installation's assigned default.
			d, err = e.AuthorizeShell(ctx, sessionID, req.ShellCommand, identity.AgentID)
			unmatched = d.ReasonCode == "no_matching_policy"
		}
	case req.ShellCommand != "":
		d = pdp.Decision{ReasonCode: "invalid_shell_request", DenySource: "policy", Reason: "shell command is only valid for the \"shell\" tool"}
	case req.Tool != "" && req.Connector == nil && e.IsV2UnregisteredTool(req.Tool) && l.isOwnerSession(sessionID):
		// Unregistered tool names receive a local policy decision by name.
		// Identity and memberships come from the verified installation-owner
		// session, never the request.
		trusted := l.trustedAgentID()
		auditTrustedAgent = true
		if trusted == "" {
			d = pdp.Decision{ReasonCode: "agent_not_assigned", DenySource: "registry", Reason: "the trusted default agent is unavailable"}
			break
		}
		if req.AgentID != "" && req.AgentID != trusted {
			d = pdp.Decision{ReasonCode: "agent_mismatch", DenySource: "registry", Reason: "the request agent is not this installation's default agent"}
			break
		}
		preq.AgentID = trusted
		d, err = e.AuthorizeV2UnregisteredTool(ctx, preq)
		unmatched = d.ReasonCode == "no_matching_policy"
	case e.IsV2HarnessTool(req.Tool):
		// The request's AgentID is untrusted: decide for the authenticated
		// runtime identity's default agent, and deny a request that names
		// any other agent instead of trusting it.
		trusted := l.trustedAgentID()
		auditTrustedAgent = true
		if trusted == "" {
			d = pdp.Decision{ReasonCode: "agent_not_assigned", DenySource: "registry", Reason: "the trusted default agent is unavailable"}
			break
		}
		if req.AgentID != "" && req.AgentID != trusted {
			d = pdp.Decision{ReasonCode: "agent_mismatch", DenySource: "registry", Reason: "the request agent is not this installation's default agent"}
			break
		}
		preq.AgentID = trusted
		d, err = e.AuthorizeV2HarnessTool(ctx, preq)
	default:
		// For v2 bundles, resolve the agent from the runtime identity.
		// For v1 bundles, delegate agent resolution to Evaluate/bundle default.
		if v, ok := e.Bundle(); ok && v.Payload.Schema == "kei.policy-bundle/v2" {
			trusted := l.trustedAgentID()
			auditTrustedAgent = true
			if trusted == "" {
				d = pdp.Decision{ReasonCode: "agent_not_assigned", DenySource: "registry", Reason: "the trusted default agent is unavailable"}
				break
			}
			if req.AgentID != "" && req.AgentID != trusted {
				d = pdp.Decision{ReasonCode: "agent_mismatch", DenySource: "registry", Reason: "the request agent is not this installation's default agent"}
				break
			}
			preq.AgentID = trusted
		}
		d, err = e.Evaluate(ctx, preq)
	}
	return d, auditTrustedAgent, unmatched, err
}

func (l *LocalPDP) isOwnerSession(sessionID string) bool {
	if sessionID == "" || sessionID == pdp.DefaultSession {
		return false
	}
	l.ownerMu.RLock()
	defer l.ownerMu.RUnlock()
	return l.ownerID == sessionID && !l.ownerUnavailable
}

// decideCredentialReleaseV2 authorizes one exact tool/connector/capability/
// resource tuple using the trusted installation agent and named session.
func (l *LocalPDP) decideCredentialReleaseV2(ctx context.Context, sessionID string, req socketAuthorizeRequest) (pdp.Decision, bool) {
	denied := func(code, reason string) (pdp.Decision, bool) {
		return pdp.Decision{ReasonCode: code, DenySource: "policy", Reason: reason, BundleState: "ready"}, true
	}
	if sessionID == pdp.DefaultSession || !l.Sessions.Exists(sessionID) {
		return denied(pdp.ReasonSessionNotFound, "v2 credential release requires a live named session")
	}
	e, identity := l.evaluator.Load(), l.identity.Load()
	if e == nil || identity == nil {
		return denied("policy_bundle_missing", "runtime identity or policy bundle is unavailable")
	}
	if sub, ok := l.Sessions.Get(sessionID); ok && sub.SubjectKind == "service_principal" {
		if _, valid := e.BundleServicePrincipalIdentity(sub.UserID, identity.AgentID); !valid {
			return denied("subject_unlinked", "the principal is no longer present for this agent")
		}
	}
	trusted := identity.AgentID
	if trusted == "" || (req.AgentID != "" && req.AgentID != trusted) {
		return denied("agent_mismatch", "the request agent is not this installation's default agent")
	}
	verified, ok := e.Bundle()
	if !ok || verified.Payload.Schema != "kei.policy-bundle/v2" {
		return denied("policy_bundle_invalid", "tool-bound credential release requires a verified v2 bundle")
	}
	connector, ok := verified.Connector(req.Connector.ConnectorID)
	if !ok {
		return denied("connector_not_registered", "connector is not described in the verified v2 bundle")
	}
	if connector.AccountModel != "shared" {
		return denied("account_model_not_supported", "tool-bound release requires a shared connector")
	}
	capabilityFound := false
	for _, capability := range connector.Capabilities {
		if capability.Name == req.Connector.Capability {
			capabilityFound = true
			break
		}
	}
	if !capabilityFound {
		return denied("capability_not_registered", "capability is not declared for the connector")
	}
	d, err := e.AuthorizeV2HarnessToolForTarget(ctx, pdp.Request{
		Session: sessionID, Tool: req.Tool, AgentID: trusted,
	}, req.Connector.ConnectorID, req.Connector.Capability, req.Resource)
	if err != nil {
		return pdp.Decision{ReasonCode: "request_canceled", DenySource: "runtime_state", Reason: "request canceled", BundleState: "ready"}, true
	}
	return d, true
}

// handleCredentialRelease serves POST /v1/credentials:release (HAI-722,
// kei-connector-contracts docs/credential-passthrough.md). It re-runs the
// /v1/authorize decision for the request and, only on allow, releases the
// session-held connector credential (value + expiry). On a policy deny, or on
// an allow whose credential is missing/expired, it returns a typed reason_code
// and no credential — never a fallback. The audit records the decision and
// whether a credential was released, never the credential value.
func (l *LocalPDP) handleCredentialRelease(w http.ResponseWriter, r *http.Request) {
	var req socketAuthorizeRequest
	if err := decodeSocketJSON(w, r, &req); err != nil || req.Schema != credentialReleaseRequestSchema {
		writeRuntimeError(w, http.StatusBadRequest, "invalid_request", "request must be a "+credentialReleaseRequestSchema+" object with no unknown fields")
		return
	}
	if req.Connector == nil || req.Connector.ConnectorID == "" || req.Connector.Capability == "" {
		writeRuntimeError(w, http.StatusBadRequest, "invalid_request", "a connector{connector_id, capability} is required for a credential release")
		return
	}
	if req.Resource == "" {
		writeRuntimeError(w, http.StatusBadRequest, "invalid_request", "a resource is required")
		return
	}
	if !validOnBehalfOf(req.OnBehalfOf) {
		writeRuntimeError(w, http.StatusBadRequest, "invalid_request", "on_behalf_of must be empty or a type-prefixed value")
		return
	}
	sessionID := session.FromRequest(r)
	if sub, ok := l.Sessions.Get(sessionID); ok && sub.SubjectKind == "service_principal" && req.Tool == "" {
		writeRuntimeError(w, http.StatusBadRequest, "invalid_request", "principal credential release requires a tool-bound shared credential request")
		return
	}
	var d pdp.Decision
	var auditTrustedAgent bool
	var err error
	if req.Tool != "" {
		d, auditTrustedAgent = l.decideCredentialReleaseV2(r.Context(), sessionID, req)
	} else {
		d, auditTrustedAgent, _, err = l.decideAuthorize(r.Context(), sessionID, req)
	}
	if err != nil {
		writeRuntimeError(w, http.StatusServiceUnavailable, "request_canceled", "request canceled")
		return
	}
	resp := socketCredentialReleaseResponse{Schema: credentialReleaseResponseSchema, Decision: "deny", ReasonCode: d.ReasonCode, Reason: d.Reason, BundleState: d.BundleState}
	if d.Allow {
		subject := ""
		if sub, ok := l.Sessions.Get(sessionID); ok {
			subject = sub.UserID
		}
		var cred *socketCredentialReleaseCred
		releaseErr := l.UseConnectorCredential(r.Context(), sessionID, subject, req.Connector.ConnectorID, req.Resource, func(c credrelease.ConnectorCredential) error {
			if req.Tool != "" && (c.ConnectorID != req.Connector.ConnectorID || c.Resource != req.Resource) {
				return errCredentialAudienceMismatch
			}
			if req.Tool != "" && c.AccountModel != "shared" {
				return errCredentialAccountModelUnsupported
			}
			cred = &socketCredentialReleaseCred{
				ConnectorID: c.ConnectorID, Issuer: c.Issuer, Resource: c.Resource,
				AccountModel: c.AccountModel, AccessToken: c.AccessToken, ExpiresAt: c.ExpiresAt,
			}
			return nil
		})
		if releaseErr != nil {
			var denied *credrelease.DeniedError
			if errors.As(releaseErr, &denied) {
				resp.ReasonCode = credentialReleaseReason(denied.Reason)
			} else if errors.Is(releaseErr, errCredentialAccountModelUnsupported) {
				resp.ReasonCode = "account_model_not_supported"
			} else if errors.Is(releaseErr, errCredentialAudienceMismatch) {
				resp.ReasonCode = "credential_audience_mismatch"
			} else {
				resp.ReasonCode = "credential_provider_unavailable"
			}
			resp.Reason = "the session credential could not be released"
		} else {
			resp.Decision = "allow"
			resp.Credential = cred
		}
	}
	if d.PolicyID != "" {
		resp.PolicyID = d.PolicyID
	}
	if d.BundleVersion > 0 {
		resp.PolicyBundleVersion, resp.PolicyBundleDigest, resp.PolicyRevision = &d.BundleVersion, d.BundleDigest, &d.PolicyRevision
	}
	if l.emit != nil {
		auditReq := req
		if auditTrustedAgent {
			auditReq.AgentID = l.trustedAgentID()
		}
		released := resp.Decision == "allow" && resp.Credential != nil
		data := l.decisionEventJSON(auditReq, sessionID, d, &released)
		l.emit(data)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

// credentialReleaseReason maps an internal credrelease deny reason to the
// HAI-722 contract's typed reason_code. An unknown I11 failure reason is
// reported as not connected.
func credentialReleaseReason(reason string) string {
	switch reason {
	case credrelease.ReasonNotConnected:
		return "credential_not_connected"
	case credrelease.ReasonReconnectRequired:
		return "credential_reconnect_required"
	case credrelease.ReasonMaxLifetimeExceeded:
		return "credential_max_lifetime_exceeded"
	case credrelease.ReasonAudienceMismatch:
		return "credential_audience_mismatch"
	case credrelease.ReasonProviderUnavailable:
		return "credential_provider_unavailable"
	case credrelease.ReasonProviderUnauthorized:
		return "credential_provider_unauthorized"
	case credrelease.ReasonNoSession:
		return "no_session"
	default:
		return "credential_not_connected"
	}
}

// trustedAgentID is the default agent of the authenticated runtime identity,
// or "" when none is assigned. It never comes from a caller's request.
func (l *LocalPDP) trustedAgentID() string {
	if identity := l.identity.Load(); identity != nil {
		return identity.AgentID
	}
	return ""
}

func socketAuthorizeResponseForDecision(d pdp.Decision, includeEnrollment bool) socketAuthorizeResponse {
	resp := socketAuthorizeResponse{
		Schema: authorizeResponseSchema, Decision: "deny", ReasonCode: d.ReasonCode,
		Hint: denyhint.Hint(d.ReasonCode), DenySource: d.DenySource, Reason: d.Reason, PolicyID: d.PolicyID,
		BundleState: d.BundleState,
	}
	if d.Allow {
		resp.Decision = policybundle.DecisionPermit
	}
	if includeEnrollment {
		resp.Enrollment = d.Enrollment
	}
	if d.BundleVersion > 0 {
		resp.PolicyBundleVersion, resp.PolicyBundleDigest, resp.PolicyRevision = &d.BundleVersion, d.BundleDigest, &d.PolicyRevision
	}
	return resp
}

func validOnBehalfOf(value string) bool {
	if value == "" {
		return true
	}
	kind, identifier, ok := strings.Cut(value, ":")
	return ok && strings.TrimSpace(kind) == kind && kind != "" && strings.TrimSpace(identifier) == identifier && identifier != ""
}

func typedSubject(subject pdp.Subject) string {
	kind := subject.SubjectKind
	if kind == "" {
		kind = "user"
	}
	if subject.UserID == "" {
		return ""
	}
	return kind + ":" + subject.UserID
}

func (l *LocalPDP) decisionEventJSON(req socketAuthorizeRequest, sessionID string, d pdp.Decision, credentialReleased *bool) json.RawMessage {
	return l.decisionEventJSONWithUnmatched(req, sessionID, d, credentialReleased, false)
}

func (l *LocalPDP) decisionEventJSONWithUnmatched(req socketAuthorizeRequest, sessionID string, d pdp.Decision, credentialReleased *bool, unmatched bool) json.RawMessage {
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
		CredentialReleased: credentialReleased,
	}
	if unmatched && d.ReasonCode == "no_matching_policy" {
		e.Decision = "unmatched"
	} else if d.Allow {
		e.Decision = "allow"
	}
	if subject, ok := l.Sessions.Get(sessionID); ok {
		e.InvokingSubject = typedSubject(subject)
	}
	if req.OnBehalfOf != "" {
		e.OnBehalfOf = req.OnBehalfOf
	}
	if sessionID != pdp.DefaultSession {
		e.SessionID = &sessionID
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

func validArgumentDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	for _, r := range value[len("sha256:"):] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func decodeSocketJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	return decodeSocketJSONLimit(w, r, dst, maxSocketRequest)
}

func decodeSocketJSONLimit(w http.ResponseWriter, r *http.Request, dst any, limit int64) error {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
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
