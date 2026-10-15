package invoke

// The serve daemon's side of POST /v1/connectors:invoke (ADR-034, owner
// option A, HAI-346 L3b). The daemon decides the call with its local PDP and
// the session subject, runs it with the session credential it holds, and
// returns only the result. The credential never leaves the daemon: it reaches
// the provider call through the credential store's Use callback and nothing
// else.
//
// Who uses it: this is the path for governed connector API calls made on
// behalf of tool calls and skills, from any harness, through `kei-proxy
// connector invoke` or the socket directly. Native CLI tools run by
// Unix/local-process harnesses use POST /v1/commands:run (internal/run)
// instead.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-contracts/setup"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/input"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/credentials/obo"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/credrelease"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/session"
	"github.com/google/uuid"
)

const (
	// DaemonInvokePath is the socket route the daemon serves.
	DaemonInvokePath            = "/v1/connectors:invoke"
	daemonRequestSchema         = "kei.connector-invoke-request/v1"
	daemonResponseSchema        = "kei.connector-invoke-response/v1"
	maxDaemonRequestBytes       = 192 << 10
	maxLegacyDaemonRequestBytes = 64 << 10
	// daemonCredentialRef names where a session connector's credential comes
	// from in its synthesized metadata; it is a label, not a reference.
	daemonCredentialRef = "kei-session-credential"
	// descriptorCredentialRef is the same label for an opaque_ref descriptor,
	// whose credential the daemon resolves through SecretResolver.
	descriptorCredentialRef = "kei-bundle-descriptor-credential"
)

// IsSessionProvider reports whether provider's default credential is the
// session subject's own OAuth connection, released by I11 under the same
// name: its kei-connector-contracts setup schema offers oauth with per_user as
// the default account model. A bundle without connector descriptors (an
// older catalog) runs only these in the daemon, as before HAI-378; with
// descriptors, each connector's credential_source and account_model decide.
func IsSessionProvider(provider string) bool {
	schema, ok := setup.SetupSchemaFor(contract.Provider(provider))
	if !ok {
		return false
	}
	for _, auth := range schema.Auth {
		if auth.CredentialSource == contract.CredentialSourceOAuth && auth.DefaultAccountModel == contract.AccountModelPerUser {
			return true
		}
	}
	return false
}

// Grant is the daemon's local decision for one connector call.
type Grant struct {
	Allow      bool
	V2Tool     bool
	ReasonCode string
	Reason     string
	Enrollment json.RawMessage
	// HasSession is false when there is no session at all.
	HasSession bool
	// Subject is the linked session user id the decision was made for, or "".
	Subject string
	AgentID string
	// Provider and Capabilities are the bundle's connector entry; Provider is
	// "" when the bundle does not know the connector.
	Provider     string
	ConnectorID  string
	Capabilities []string
	TenantID     string
	WorkspaceID  string
	// Connector is the bundle's descriptor for the connector (HAI-378), from
	// the same bundle as the decision, or nil. Descriptors reports whether the
	// bundle carries descriptors at all: without them the daemon keeps its
	// session-OAuth-only behavior.
	Connector   *policybundle.Connector
	Descriptors bool
}

// DaemonCall is what the daemon asks its PDP to decide. Session is the id of
// the session the call runs in ("" for the legacy default session).
type DaemonCall struct {
	Session                                    string
	ConnectorID, Capability, Resource, AgentID string
	ToolName                                   string
}

// ReasonSessionNotFound is the PDP's deny reason for a session id that is
// not live (pdp.ReasonSessionNotFound).
const ReasonSessionNotFound = "session_not_found"

// Daemon serves POST /v1/connectors:invoke inside the serve daemon. The
// caller authenticates the request before ServeHTTP.
type Daemon struct {
	// Env carries the provider seams (ProviderTransport, LookupIP, Now) and
	// the audit sink. Its catalog and secret-store fields are unused.
	Env Env
	// Authorize decides a call with the local PDP and the session subject.
	Authorize func(context.Context, DaemonCall) (Grant, error)
	// PlanV2 resolves the trusted registered planner for tool and canonical args.
	PlanV2 func(context.Context, string, string, string, []byte, []byte, string, int) ([]policybundle.Operation, error)
	// ValidateV2 confirms the full current plan matches the opaque context.
	ValidateV2 func(context.Context, string, string, string, string, []byte, []byte, []policybundle.Operation, string, int) error
	// ConsumeV2Plan atomically consumes the complete plan before provider work.
	ConsumeV2Plan func(context.Context, string, string, string, string, []byte, []byte, []policybundle.Operation, string, int) error
	// UseCredential runs fn with the named session credential for subject/provider.
	UseCredential func(ctx context.Context, session, subject, provider string, fn func(token string) error) error
	// Secrets resolves opaque_ref descriptors' credentials (HAI-378).
	Secrets SecretResolver
	// Assertions checks a user_assertion against the session subject for an
	// on_behalf_of connector (HAI-669); nil denies every such call.
	Assertions AssertionChecker
}

// maxUserAssertionBytes bounds the user token a harness hands over.
const maxUserAssertionBytes = 16 << 10

// AssertionChecker is the on_behalf_of exchanger's pre-exchange check
// (obo.Exchanger.CheckAssertion): the descriptor, the token's tenant, and
// that its user is the session subject's own Entra identity. It sends
// nothing and keeps nothing.
type AssertionChecker interface {
	CheckAssertion(subject, connectorID, assertion string) error
}

// checkUserAssertion gates the per-call user token (ADR-036 amendment
// 2026-10-15, decision 3). An on_behalf_of connector requires one that
// passes the checker for the session subject; any other connector refuses
// one, so a token is never silently accepted. The token is used for this
// check only and never appears in an outcome, a log line or audit.
func (d *Daemon) checkUserAssertion(g Grant, assertion string) *denial {
	if len(assertion) > maxUserAssertionBytes {
		return deny("assertion_invalid", "the user token exceeds the size limit")
	}
	onBehalfOf := g.Descriptors && g.Connector != nil && contract.CredentialSource(g.Connector.CredentialSource) == contract.CredentialSourceOnBehalfOf
	if !onBehalfOf {
		if assertion != "" {
			return deny("assertion_not_applicable", "user_assertion is accepted only for on_behalf_of connectors")
		}
		return nil
	}
	if assertion == "" {
		return deny("assertion_required", "an on_behalf_of connector needs the user's token in user_assertion")
	}
	if d.Assertions == nil {
		return deny("credential_source_not_supported", "this daemon does not run on_behalf_of connectors")
	}
	if err := d.Assertions.CheckAssertion(g.Subject, g.Connector.ID, assertion); err != nil {
		var checkErr *obo.Error
		if errors.As(err, &checkErr) {
			return deny(checkErr.Code, checkErr.Reason)
		}
		return deny("assertion_invalid", "the user token could not be checked")
	}
	return nil
}

// daemonRequest is the route's body. It names the call only: the subject
// comes from the daemon's session and the credential from its store.
type daemonRequest struct {
	Schema          string          `json:"schema"`
	ToolName        string          `json:"tool_name,omitempty"`
	PreflightHandle string          `json:"preflight_handle,omitempty"`
	SessionID       string          `json:"session_id,omitempty"`
	ParentSpan      string          `json:"parent_span,omitempty"`
	DelegationDepth int             `json:"delegation_depth,omitempty"`
	ConnectorID     string          `json:"connector_id"`
	Capability      string          `json:"capability"`
	Action          string          `json:"action"`
	Resource        string          `json:"resource"`
	Input           json.RawMessage `json:"input,omitempty"`
	Context         json.RawMessage `json:"context,omitempty"`
	TraceID         string          `json:"trace_id,omitempty"`
	IdempotencyKey  string          `json:"idempotency_key,omitempty"`
	AgentID         string          `json:"agent_id,omitempty"`
	Framework       string          `json:"framework,omitempty"`
	UserAssertion   string          `json:"user_assertion,omitempty"`
}

// daemonResponse is the route's answer: the same object `connector invoke`
// prints, with a schema.
type daemonResponse struct {
	Schema string `json:"schema"`
	output
}

func (d *Daemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req daemonRequest
	body, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, maxDaemonRequestBytes))
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	decodeErr := dec.Decode(&req)
	if decodeErr == nil {
		var extra any
		if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
			decodeErr = errors.New("trailing JSON")
		}
	}
	if readErr != nil || decodeErr != nil || req.Schema != daemonRequestSchema {
		writeDaemonError(w, http.StatusBadRequest, "invalid_request", "request must be a "+daemonRequestSchema+" object with no unknown fields")
		return
	}
	if req.ToolName != "" {
		// The authenticated socket middleware may bind a tokenless owner
		// request to its pinned session. Let that trusted session header supply
		// the body field; callers must not need to discover the opaque owner ID.
		boundSession := session.FromRequest(r)
		if req.SessionID == "" {
			req.SessionID = boundSession
		}
		if req.SessionID == "" || boundSession != req.SessionID {
			writeDaemonError(w, http.StatusBadRequest, "invalid_request", "v2 invoke requires the matching named session")
			return
		}
	}
	if req.ToolName == "" && len(body) > maxLegacyDaemonRequestBytes {
		writeDaemonError(w, http.StatusBadRequest, "invalid_request", "legacy request exceeds the size limit")
		return
	}
	if req.ToolName != "" && policybundle.RejectDuplicateJSON(body) != nil {
		writeDaemonError(w, http.StatusBadRequest, "invalid_request", "v2 request contains ambiguous JSON")
		return
	}
	if (req.ToolName == "") != (req.PreflightHandle == "") || (req.ToolName == "" && (req.ConnectorID == "" || req.Capability == "" || req.Action == "" || req.Resource == "")) || (req.ToolName != "" && (req.SessionID == "" || req.ConnectorID != "" || req.Capability != "" || req.Action != "" || req.Resource != "")) {
		writeDaemonError(w, http.StatusBadRequest, "invalid_request", "a legacy operation or a v2 tool and preflight handle are required")
		return
	}
	if req.TraceID == "" {
		req.TraceID = uuid.NewString()
	}
	out := d.invoke(r.Context(), session.FromRequest(r), req)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(daemonResponse{Schema: daemonResponseSchema, output: out})
}

// invoke decides, runs and audits one call in session sessionID and returns
// what the caller sees.
func (d *Daemon) invoke(ctx context.Context, sessionID string, dr daemonRequest) output {
	started := time.Now()
	plan := connectorInvokePlan{req: Request{
		AgentID: dr.AgentID, ConnectorID: dr.ConnectorID, Capability: dr.Capability, Action: dr.Action,
		Resource: dr.Resource, TraceID: dr.TraceID, IdempotencyKey: dr.IdempotencyKey, Framework: dr.Framework,
	}, session: sessionID}
	out := output{TraceID: dr.TraceID, ConnectorID: dr.ConnectorID, Capability: dr.Capability}
	var exec *execution
	finish := func(dn *denial) output {
		if dn != nil {
			out.Decision, out.ReasonCode, out.Reason, out.Result, out.Audit = "deny", dn.code, dn.reason, nil, nil
		}
		d.Env.emitAudit(plan, exec, out, time.Since(started))
		return out
	}

	raw := []byte(dr.Input)
	if dr.ToolName != "" && len(raw) > policybundle.MaxPlanDataBytes || dr.ToolName == "" && len(raw) > input.MaxBytes {
		return finish(deny("input_invalid", "input exceeds the connector input size limit"))
	}
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	if dr.ToolName != "" && policybundle.RejectDuplicateJSON(raw) != nil {
		return finish(deny("input_invalid", "tool arguments contain ambiguous JSON"))
	}
	canonical, digest, err := input.Canonicalize(raw)
	if err != nil {
		return finish(deny("input_invalid", "input must be one JSON object"))
	}
	if dr.ToolName != "" && len(canonical) > policybundle.MaxPlanDataBytes || dr.ToolName == "" && len(canonical) > input.MaxBytes {
		return finish(deny("input_invalid", "input exceeds the connector input size limit"))
	}
	plan.req.InputDigest = digest
	out.Audit = &outputAudit{InputDigest: digest}
	if dr.ToolName != "" {
		return d.invokeV2(ctx, dr, plan, canonical, started, out)
	}

	grant, err := d.Authorize(ctx, DaemonCall{Session: sessionID, ConnectorID: dr.ConnectorID, Capability: dr.Capability, Resource: dr.Resource, AgentID: dr.AgentID})
	if err != nil {
		return finish(deny("request_canceled", "request canceled"))
	}
	plan.req.InvokingSubject = grant.Subject
	if grant.ReasonCode == ReasonSessionNotFound {
		return finish(deny(ReasonSessionNotFound, "the session does not exist or has ended"))
	}
	if !grant.HasSession {
		return finish(deny("no_session", "no active session: start one with PUT /v1/session"))
	}
	if !grant.Allow {
		if len(grant.Enrollment) > 0 {
			enrollment := append(json.RawMessage(nil), grant.Enrollment...)
			out.Enrollment = &enrollment
		}
		return finish(deny(grant.ReasonCode, grant.Reason))
	}
	if grant.Subject == "" {
		return finish(deny("subject_unlinked", "the session subject is not linked"))
	}
	if dn := d.checkUserAssertion(grant, dr.UserAssertion); dn != nil {
		return finish(dn)
	}

	exec = &execution{provider: contract.Provider(grant.Provider)}
	meta, inv, secret, dn := daemonCall(grant, dr)
	if dn != nil {
		return finish(dn)
	}
	exec.meta, exec.invocation = &meta, &inv
	conn, in, dn := d.Env.prepare(plan.req, canonical, meta, inv)
	if dn != nil {
		return finish(dn)
	}
	exec.credentialSubject = contract.CredentialSubject(meta, inv)

	err = d.useCredential(ctx, sessionID, grant.Subject, meta, secret, func(token string) error {
		status, runDenial := d.Env.run(ctx, conn, meta, inv, in, token, exec)
		dn = runDenial
		if runDenial != nil && status == http.StatusUnauthorized {
			return credrelease.ErrProviderUnauthorized
		}
		return nil
	})
	if err != nil {
		cd, connect := credentialDenial(err)
		if connect != nil {
			out.Connect = connect
		}
		return finish(cd)
	}
	if dn != nil {
		return finish(dn)
	}
	out.Provider = string(meta.Provider)
	out.Decision, out.Result = "allow", exec.result
	out.Audit.ResultDigest, out.Audit.ResultBytes = sha256Digest(exec.result), len(exec.result)
	return finish(nil)
}

// daemonCall builds the metadata and invocation for a granted call, and
// names the descriptor whose tenant-stored secret the call needs (nil: the
// session's own OAuth credential). A bundle with connector descriptors
// decides by each descriptor's credential_source and account_model; a bundle
// without them keeps the pre-descriptor session-provider rule.
func daemonCall(g Grant, dr daemonRequest) (contract.Metadata, contract.Invocation, *policybundle.Connector, *denial) {
	if g.Descriptors {
		return descriptorCall(g, dr)
	}
	meta, inv, dn := sessionCall(g, dr)
	return meta, inv, nil, dn
}

// descriptorCall builds the call from the connector's bundle descriptor
// (ADR-034, HAI-378). The descriptor is consulted only after an allow; the
// contract checks in prepare (setup.ValidateMetadata, http_api validation)
// still run on the metadata it yields.
func descriptorCall(g Grant, dr daemonRequest) (contract.Metadata, contract.Invocation, *policybundle.Connector, *denial) {
	c := g.Connector
	if c == nil || c.ID != dr.ConnectorID || (g.ConnectorID != "" && c.ID != g.ConnectorID) || c.Provider == "" {
		return contract.Metadata{}, contract.Invocation{}, nil, deny("descriptor_invalid", "the policy bundle has no descriptor for this connector")
	}
	if contract.AccountModel(c.AccountModel) == contract.AccountModelDomainDelegation {
		return contract.Metadata{}, contract.Invocation{}, nil, deny("account_model_not_supported", "domain-wide delegation is not executed yet")
	}
	provider := contract.Provider(c.Provider)
	declared := make([]string, 0, len(c.Capabilities))
	for _, capability := range c.Capabilities {
		declared = append(declared, capability.Name)
	}
	meta, inv, dn := callMetadata(g, dr, provider, declared)
	if dn != nil {
		return contract.Metadata{}, contract.Invocation{}, nil, dn
	}
	if c.Name != "" {
		meta.Name = c.Name
	}
	meta.Config, meta.HTTPAPI, meta.Grafana = c.Config, c.HTTPAPI, c.Grafana
	switch contract.CredentialSource(c.CredentialSource) {
	case contract.CredentialSourceOAuth:
		if contract.AccountModel(c.AccountModel) != contract.AccountModelPerUser {
			return contract.Metadata{}, contract.Invocation{}, nil, deny("credential_source_not_supported", "the daemon runs oauth connectors only with the session's own connection")
		}
		return meta, inv, nil, nil
	case contract.CredentialSourceOpaqueRef:
		// The account is the connector's own (contract.CredentialSubject is
		// its shared subject); the contract's account models apply to oauth.
		meta.CredentialSource, meta.AccountModel, meta.CredentialRef = contract.CredentialSourceOpaqueRef, "", descriptorCredentialRef
		return meta, inv, c, nil
	case contract.CredentialSourceOnBehalfOf:
		// The user_assertion gate already ran; injecting the exchanged token
		// is HAI-669 R3.
		return contract.Metadata{}, contract.Invocation{}, nil, deny("credential_source_not_supported", "on_behalf_of connectors are not executed yet")
	}
	return contract.Metadata{}, contract.Invocation{}, nil, deny("descriptor_invalid", "the descriptor's credential source is not supported")
}

// sessionCall builds the per_user OAuth metadata and invocation for a granted
// call from a bundle without connector descriptors. Only session providers
// qualify.
func sessionCall(g Grant, dr daemonRequest) (contract.Metadata, contract.Invocation, *denial) {
	if g.Provider == "" {
		return contract.Metadata{}, contract.Invocation{}, deny("descriptor_invalid", "the policy bundle does not describe this connector")
	}
	if !IsSessionProvider(g.Provider) {
		return contract.Metadata{}, contract.Invocation{}, deny("credential_source_not_supported", "the daemon runs only connectors that use the session's own OAuth connection")
	}
	return callMetadata(g, dr, contract.Provider(g.Provider), g.Capabilities)
}

// callMetadata builds per_user OAuth session metadata and the invocation for
// provider. Only capabilities both the bundle and this runtime's contracts
// version declare are kept, and the requested one must be among them.
func callMetadata(g Grant, dr daemonRequest, provider contract.Provider, declaredNames []string) (contract.Metadata, contract.Invocation, *denial) {
	declared := map[string]bool{}
	for _, name := range declaredNames {
		declared[name] = true
	}
	var caps []contract.Capability
	var action contract.Action
	for _, c := range contract.CapabilitiesFor(provider) {
		if declared[c.Name] {
			caps = append(caps, c)
		}
		if c.Name == dr.Capability {
			action = c.Action
		}
	}
	if !declared[dr.Capability] || action == "" {
		return contract.Metadata{}, contract.Invocation{}, deny("descriptor_invalid", "capability is not declared on the connector")
	}
	if string(action) != dr.Action {
		return contract.Metadata{}, contract.Invocation{}, deny("descriptor_invalid", "action does not match the capability")
	}
	meta := contract.Metadata{
		ID: dr.ConnectorID, TenantID: g.TenantID, WorkspaceID: g.WorkspaceID, Name: dr.ConnectorID,
		Provider: provider, Status: contract.StatusActive, CredentialRef: daemonCredentialRef,
		Scopes: []string{"session"}, Capabilities: caps, CreatedBy: "kei-proxy",
		CredentialSource: contract.CredentialSourceOAuth, AccountModel: contract.AccountModelPerUser,
	}
	inv := contract.Invocation{
		TenantID: g.TenantID, WorkspaceID: g.WorkspaceID, Subject: g.Subject, AgentID: dr.AgentID,
		ConnectorID: dr.ConnectorID, Capability: dr.Capability, Action: action, Resource: dr.Resource,
		TraceID: dr.TraceID, IdempotencyKey: dr.IdempotencyKey,
	}
	if inv.AgentID == "" {
		// The PDP decided for the bundle's default agent; the invocation
		// needs an identifier, and this one is recorded as such in audit.
		inv.AgentID = "bundle-default-agent"
	}
	return meta, inv, nil
}

// useCredential runs fn with the call's credential: the session's own OAuth
// credential, or, for an opaque_ref descriptor, the tenant-stored secret
// SecretResolver reads. A rejected secret is not re-fetched: the provider's
// 401 stays the call's denial.
func (d *Daemon) useCredential(ctx context.Context, sessionID, subject string, meta contract.Metadata, secret *policybundle.Connector, fn func(token string) error) error {
	if secret == nil {
		return d.UseCredential(ctx, sessionID, subject, string(meta.Provider), fn)
	}
	return UseSecret(ctx, d.Secrets, *secret, fn)
}

// UseSecret runs fn with descriptor c's tenant-stored credential. The value
// is in scope only while fn runs.
func UseSecret(ctx context.Context, r SecretResolver, c policybundle.Connector, fn func(value string) error) error {
	value, err := r.Resolve(ctx, c)
	if err != nil {
		return err
	}
	if err := fn(value); err != nil && !errors.Is(err, credrelease.ErrProviderUnauthorized) {
		return err
	}
	return nil
}

// CredentialDenial maps a credential store refusal to a reason code and
// reason, and to a connect hint when reconnecting the provider would fix it.
func CredentialDenial(err error) (code, reason string, connect *json.RawMessage) {
	dn, connect := credentialDenial(err)
	return dn.code, dn.reason, connect
}

func credentialDenial(err error) (*denial, *json.RawMessage) {
	var se *SecretError
	if errors.As(err, &se) {
		return deny(se.Code, se.Reason), nil
	}
	var de *credrelease.DeniedError
	if !errors.As(err, &de) {
		return deny("credential_unavailable", "session credential is not available"), nil
	}
	var dn *denial
	switch de.Reason {
	case credrelease.ReasonNoSession:
		dn = deny("no_session", "the session ended or changed during the call")
	case credrelease.ReasonNotConnected:
		dn = deny("connector_not_connected", "the session subject has not connected this provider")
	case credrelease.ReasonReconnectRequired, credrelease.ReasonMaxLifetimeExceeded, credrelease.ReasonProviderUnauthorized:
		dn = deny("connector_reconnect_required", "the provider connection must be reconnected")
	case "SUBJECT_UNLINKED":
		dn = deny("subject_unlinked", "the session subject is not linked")
	default:
		dn = deny("credential_unavailable", "session credential is not available")
	}
	if !de.Connect() {
		return dn, nil
	}
	hint, _ := json.Marshal(map[string]string{"provider": de.Provider, "reason": de.Reason})
	raw := json.RawMessage(hint)
	return dn, &raw
}

func writeDaemonError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"message": message, "type": "runtime_error", "code": code},
	})
}
