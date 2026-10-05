package invoke

// The serve daemon's side of POST /v1/connectors:invoke (ADR-034, owner
// option A, HAI-346 L3b). The daemon decides the call with its local PDP and
// the session subject, runs it with the session credential it holds, and
// returns only the result. The credential never leaves the daemon: it reaches
// the provider call through the credential store's Use callback and nothing
// else.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/input"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/credrelease"
	"github.com/google/uuid"
)

const (
	// DaemonInvokePath is the socket route the daemon serves.
	DaemonInvokePath      = "/v1/connectors:invoke"
	daemonRequestSchema   = "kei.connector-invoke-request/v1"
	daemonResponseSchema  = "kei.connector-invoke-response/v1"
	maxDaemonRequestBytes = 64 << 10
	// daemonCredentialRef names where a session connector's credential comes
	// from in its synthesized metadata; it is a label, not a reference.
	daemonCredentialRef = "kei-session-credential"
)

// IsSessionProvider reports whether provider's credential is the session
// subject's own OAuth connection, released by I11 under the same name. Only
// these run in the daemon; every other provider needs connector config and a
// credential the bundle does not carry.
func IsSessionProvider(provider string) bool { return sessionProviders[contract.Provider(provider)] }

var sessionProviders = map[contract.Provider]bool{
	contract.ProviderGitHub: true,
	contract.ProviderGmail:  true,
	contract.ProviderGoogle: true,
	contract.ProviderLinear: true,
}

// Grant is the daemon's local decision for one connector call.
type Grant struct {
	Allow      bool
	ReasonCode string
	Reason     string
	Enrollment json.RawMessage
	// HasSession is false when there is no session at all.
	HasSession bool
	// Subject is the linked session user id the decision was made for, or "".
	Subject string
	// Provider and Capabilities are the bundle's connector entry; Provider is
	// "" when the bundle does not know the connector.
	Provider     string
	Capabilities []string
	TenantID     string
	WorkspaceID  string
}

// DaemonCall is what the daemon asks its PDP to decide.
type DaemonCall struct {
	ConnectorID, Capability, Resource, AgentID string
}

// Daemon serves POST /v1/connectors:invoke inside the serve daemon. The
// caller authenticates the request before ServeHTTP.
type Daemon struct {
	// Env carries the provider seams (ProviderTransport, LookupIP, Now) and
	// the audit sink. Its catalog and secret-store fields are unused.
	Env Env
	// Authorize decides a call with the local PDP and the session subject.
	Authorize func(context.Context, DaemonCall) (Grant, error)
	// UseCredential runs fn with the session credential subject holds for
	// provider (credrelease.Store.Use).
	UseCredential func(ctx context.Context, subject, provider string, fn func(token string) error) error
}

// daemonRequest is the route's body. It names the call only: the subject
// comes from the daemon's session and the credential from its store.
type daemonRequest struct {
	Schema         string          `json:"schema"`
	ConnectorID    string          `json:"connector_id"`
	Capability     string          `json:"capability"`
	Action         string          `json:"action"`
	Resource       string          `json:"resource"`
	Input          json.RawMessage `json:"input,omitempty"`
	TraceID        string          `json:"trace_id,omitempty"`
	IdempotencyKey string          `json:"idempotency_key,omitempty"`
	AgentID        string          `json:"agent_id,omitempty"`
	Framework      string          `json:"framework,omitempty"`
}

// daemonResponse is the route's answer: the same object `connector invoke`
// prints, with a schema.
type daemonResponse struct {
	Schema string `json:"schema"`
	output
}

func (d *Daemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req daemonRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxDaemonRequestBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.Schema != daemonRequestSchema || dec.More() {
		writeDaemonError(w, http.StatusBadRequest, "invalid_request", "request must be a "+daemonRequestSchema+" object with no unknown fields")
		return
	}
	if req.ConnectorID == "" || req.Capability == "" || req.Action == "" || req.Resource == "" {
		writeDaemonError(w, http.StatusBadRequest, "invalid_request", "connector_id, capability, action and resource are required")
		return
	}
	if req.TraceID == "" {
		req.TraceID = uuid.NewString()
	}
	out := d.invoke(r.Context(), req)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(daemonResponse{Schema: daemonResponseSchema, output: out})
}

// invoke decides, runs and audits one call and returns what the caller sees.
func (d *Daemon) invoke(ctx context.Context, dr daemonRequest) output {
	started := time.Now()
	plan := connectorInvokePlan{req: Request{
		AgentID: dr.AgentID, ConnectorID: dr.ConnectorID, Capability: dr.Capability, Action: dr.Action,
		Resource: dr.Resource, TraceID: dr.TraceID, IdempotencyKey: dr.IdempotencyKey, Framework: dr.Framework,
	}}
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
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	canonical, digest, err := input.Canonicalize(raw)
	if err != nil {
		return finish(deny("input_invalid", "input must be one JSON object of at most 16 KiB"))
	}
	plan.req.InputDigest = digest
	out.Audit = &outputAudit{InputDigest: digest}

	grant, err := d.Authorize(ctx, DaemonCall{ConnectorID: dr.ConnectorID, Capability: dr.Capability, Resource: dr.Resource, AgentID: dr.AgentID})
	if err != nil {
		return finish(deny("request_canceled", "request canceled"))
	}
	plan.req.InvokingSubject = grant.Subject
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

	exec = &execution{provider: contract.Provider(grant.Provider)}
	meta, inv, dn := sessionCall(grant, dr)
	if dn != nil {
		return finish(dn)
	}
	exec.meta, exec.invocation = &meta, &inv
	conn, in, dn := d.Env.prepare(plan.req, canonical, meta, inv)
	if dn != nil {
		return finish(dn)
	}
	exec.credentialSubject = contract.CredentialSubject(meta, inv)

	err = d.UseCredential(ctx, grant.Subject, string(meta.Provider), func(token string) error {
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

// sessionCall builds the per_user OAuth metadata and invocation for a granted
// call from the bundle's connector entry and the installation audience. Only
// session providers qualify, and only capabilities both the bundle and the
// contract declare.
func sessionCall(g Grant, dr daemonRequest) (contract.Metadata, contract.Invocation, *denial) {
	provider := contract.Provider(g.Provider)
	if g.Provider == "" {
		return contract.Metadata{}, contract.Invocation{}, deny("descriptor_invalid", "the policy bundle does not describe this connector")
	}
	if !sessionProviders[provider] {
		return contract.Metadata{}, contract.Invocation{}, deny("credential_source_not_supported", "the daemon runs only connectors that use the session's own OAuth connection")
	}
	declared := map[string]bool{}
	for _, name := range g.Capabilities {
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

// CredentialDenial maps a credential store refusal to a reason code and
// reason, and to a connect hint when reconnecting the provider would fix it.
func CredentialDenial(err error) (code, reason string, connect *json.RawMessage) {
	dn, connect := credentialDenial(err)
	return dn.code, dn.reason, connect
}

func credentialDenial(err error) (*denial, *json.RawMessage) {
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
