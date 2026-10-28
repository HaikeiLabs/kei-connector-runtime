// Package pdp is kei-proxy's Go contract / in-process policy evaluator
// (ADR-011, ADR-026). It decides governed calls from the persisted policy
// bundle and the in-memory session subject, with no network call per decision.
// The bundle schema validator is registered by the kei-connector-runtime root
// package; without it every bundle fails validation and every call is denied.
package pdp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

// Audience is the runtime installation the bundle must be issued to. It comes
// from whoami once, when the process starts.
type Audience struct {
	InstallationID string
	OrgID          string
	WorkspaceID    string
}

// ConnectorTarget selects the connector path: the registered tool is found by
// connector and capability, and the agent must be bound to the capability.
type ConnectorTarget struct {
	ConnectorID string
	Capability  string
}

// Request is one governed call. It has no subject field: the acting subject
// comes only from the in-memory session that Session names.
type Request struct {
	// Session is the id of the session the call runs in (Sessions.Create);
	// empty or non-live ids deny with session_not_found.
	Session   string
	Tool      string // registry name in the bundle's policy_set.tools
	Action    string // optional; must equal the registered action
	Resource  string
	AgentID   string // optional; the bundle's default agent when empty
	Connector *ConnectorTarget
}

// Decision is the local outcome. Every runtime failure is a deny with a
// reason code; there is no default permit.
type Decision struct {
	Allow          bool
	Reason         string
	ReasonCode     string
	DenySource     string // runtime_state | registry | identity | policy
	PolicyID       string
	BundleVersion  int64
	BundleDigest   string
	PolicyRevision int64
	BundleState    string
	Enrollment     json.RawMessage // only with subject_unlinked
}

// Evaluator decides calls against the bundle persisted in a state directory.
type Evaluator struct {
	store       *policybundle.Store
	aud         Audience
	sessions    *Sessions
	now         func() time.Time
	memberships func(*policybundle.Verified, time.Time) policybundle.Memberships
}

// New opens the policy state directory. sessions may be nil, in which case
// there is never a session subject and human-source policies deny.
func New(stateDir string, aud Audience, sessions *Sessions) (*Evaluator, error) {
	if aud.InstallationID == "" || aud.OrgID == "" || aud.WorkspaceID == "" {
		return nil, errors.New("pdp: audience requires installation, org and workspace ids")
	}
	store, err := policybundle.OpenStore(stateDir)
	if err != nil {
		return nil, err
	}
	return &Evaluator{store: store, aud: aud, sessions: sessions, now: time.Now, memberships: policybundle.BundleMembershipsAt}, nil
}

// Evaluate decides one call. The error is non-nil only when ctx is done.
func (e *Evaluator) Evaluate(ctx context.Context, req Request) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	if live, reason := e.sessionLive(req.Session); !live {
		return sessionDenial(reason), nil
	}
	v, state, err := e.check()
	if err != nil {
		return stateDenial(state), nil
	}
	d, _ := e.evaluate(v, state, req)
	return d, nil
}

// sessionLive reports whether the named session can be used. Empty ids are
// never live; a named id is live only while it is in the session store. When
// false, the returned string is the denial reason code.
func (e *Evaluator) sessionLive(id string) (bool, string) {
	if id == DefaultSession {
		return false, ReasonSessionNotFound
	}
	if e.sessions == nil {
		return false, ReasonSessionNotFound
	}
	return e.sessions.liveWithReason(id)
}

func sessionDenial(reasonCode ...string) Decision {
	code := ReasonSessionNotFound
	if len(reasonCode) > 0 && reasonCode[0] != "" {
		code = reasonCode[0]
	}
	reason := "the session does not exist or has ended"
	if code == ReasonSessionRevalidationRequired {
		reason = "the session has exceeded its max age and must be revalidated"
	}
	return Decision{Reason: reason, ReasonCode: code, DenySource: "identity"}
}

// Connector is a connector entry from the policy bundle.
type Connector = policybundle.Connector

// ConnectorGrant is a connector call's decision together with what the daemon
// needs to run it, all from the same bundle and session snapshot.
type ConnectorGrant struct {
	Decision
	// Connector is the bundle's entry for the requested connector, if any.
	Connector *Connector
	// Descriptors is true when the bundle carries connector descriptors
	// (HAI-378): Connector is then the connector's descriptor, and a missing
	// entry is a broken bundle rather than an older catalog.
	Descriptors bool
	// Subject is the session subject the decision was made for (no token);
	// HasSession is false when there was no session.
	Subject    Subject
	HasSession bool
}

// EvaluateConnector decides a connector call (req.Connector is required) and
// returns the bundle connector and session subject it was decided with. The
// error is non-nil only when ctx is done.
func (e *Evaluator) EvaluateConnector(ctx context.Context, req Request) (ConnectorGrant, error) {
	if err := ctx.Err(); err != nil {
		return ConnectorGrant{}, err
	}
	if req.Connector == nil {
		return ConnectorGrant{Decision: Decision{Reason: "connector target is required", ReasonCode: "tool_not_registered", DenySource: "registry"}}, nil
	}
	if live, reason := e.sessionLive(req.Session); !live {
		return ConnectorGrant{Decision: sessionDenial(reason)}, nil
	}
	v, state, err := e.check()
	if err != nil {
		return ConnectorGrant{Decision: stateDenial(state)}, nil
	}
	d, current := e.evaluate(v, state, req)
	g := ConnectorGrant{Decision: d}
	if current != nil {
		g.Subject, g.HasSession = *current, true
		g.Subject.Token, g.Subject.Enrollment = "", nil
	}
	if c, ok := v.Connector(req.Connector.ConnectorID); ok {
		g.Connector = &c
	}
	g.Descriptors = v.CarriesConnectorDescriptors()
	return g, nil
}

// evaluate decides req against v and returns the session subject it used.
func (e *Evaluator) evaluate(v *policybundle.Verified, state policybundle.State, req Request) (Decision, *Subject) {
	call := policybundle.Call{Tool: req.Tool, Action: req.Action, Resource: req.Resource, AgentID: req.AgentID}
	if req.Connector != nil {
		call.ConnectorID, call.Capability, call.ConnectorInvocation = req.Connector.ConnectorID, req.Connector.Capability, true
	}
	var subject *policybundle.SessionSubject
	var current Subject
	var used *Subject
	if e.sessions != nil {
		var ok bool
		if current, ok = e.sessions.Get(req.Session); ok {
			subject = &policybundle.SessionSubject{UserID: current.UserID, Email: current.Email, Source: current.Source, ExternalID: current.ExternalID, Status: string(current.Status)}
			used = &current
		}
	}
	now := e.now().UTC()
	d := v.EvaluateSessionAt(call, subject, e.memberships(v, now), now)
	out := Decision{
		Allow:          d.Outcome == "allow",
		Reason:         d.Reason,
		ReasonCode:     d.ReasonCode,
		DenySource:     denySource(d.ReasonCode),
		PolicyID:       d.PolicyID,
		BundleVersion:  v.Payload.BundleVersion,
		BundleDigest:   v.Digest,
		PolicyRevision: v.Payload.PolicyRevision,
		BundleState:    string(state),
	}
	if out.ReasonCode == "subject_unlinked" && subject != nil && len(current.Enrollment) > 0 {
		out.Enrollment = append(json.RawMessage(nil), current.Enrollment...)
	}
	return out, used
}

// HarnessCall is a pre-built harness tool call (ADR-029 §1.2, §1.3).
type HarnessCall = policybundle.HarnessCall

// HarnessResult is the kei.harness-match/v1 outcome: permit, deny, unmatched
// or not_renderable, the deciding policy, and a reason code for non-permit,
// non-deny outcomes (ADR-029 §1.5 extension).
type HarnessResult struct {
	Outcome  string
	PolicyID string
	Reason   string
}

// EvaluateHarness applies kei.harness-match/v1 to a harness tool call. A bundle
// that is missing, invalid or expired gives not_renderable, so nothing is
// rendered from it.
func (e *Evaluator) EvaluateHarness(ctx context.Context, call HarnessCall) (HarnessResult, error) {
	if err := ctx.Err(); err != nil {
		return HarnessResult{}, err
	}
	v, state, err := e.check()
	if err != nil {
		reason := policybundle.HarnessReasonBundleInvalid
		if state == policybundle.Cold || state == "" {
			// No bundle at all, not a decode error.
		}
		return HarnessResult{Outcome: policybundle.HarnessNotRenderable, Reason: reason}, nil
	}
	outcome, policyID, reason := v.EvaluateHarness(call)
	return HarnessResult{Outcome: outcome, PolicyID: policyID, Reason: reason}, nil
}

// AuthorizeV2HarnessTool evaluates a registered harness-executor tool for the
// subject held by a live named session. It never accepts a caller-supplied
// subject and does not execute the harness tool.
func (e *Evaluator) AuthorizeV2HarnessTool(ctx context.Context, req Request) (Decision, error) {
	return e.authorizeV2HarnessTool(ctx, req, "", "", "")
}

// AuthorizeV2HarnessToolForTarget evaluates a harness-executed tool against
// its exact connector release target in the same decision.
func (e *Evaluator) AuthorizeV2HarnessToolForTarget(ctx context.Context, req Request, connectorID, capability, resource string) (Decision, error) {
	return e.authorizeV2HarnessTool(ctx, req, connectorID, capability, resource)
}

// AuthorizeV2UnregisteredTool evaluates an unregistered tool name for the
// verified installation-owner subject held by a live named session.
func (e *Evaluator) AuthorizeV2UnregisteredTool(ctx context.Context, req Request) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	if req.Session == DefaultSession {
		return Decision{Reason: "v2 unregistered-tool authorization requires a named session", ReasonCode: "session_required", DenySource: "identity"}, nil
	}
	if live, reason := e.sessionLive(req.Session); !live {
		return sessionDenial(reason), nil
	}
	v, state, err := e.check()
	if err != nil {
		return stateDenial(state), nil
	}
	var subject *policybundle.SessionSubject
	if current, ok := e.sessions.Get(req.Session); ok {
		subject = &policybundle.SessionSubject{UserID: current.UserID, Email: current.Email, Source: current.Source, ExternalID: current.ExternalID, Status: string(current.Status)}
	}
	d := v.EvaluateV2UnregisteredTool(req.Tool, req.AgentID, subject, e.now().UTC())
	return Decision{Allow: d.Outcome == "allow", Reason: d.Reason, ReasonCode: d.ReasonCode, DenySource: denySource(d.ReasonCode), PolicyID: d.PolicyID, BundleVersion: v.Payload.BundleVersion, BundleDigest: v.Digest, PolicyRevision: v.Payload.PolicyRevision, BundleState: string(state)}, nil
}

// IsV2UnregisteredTool reports whether name has no tool registration in the
// currently verified v2 bundle.
func (e *Evaluator) IsV2UnregisteredTool(name string) bool {
	v, ok := e.Bundle()
	return ok && v.Payload.Schema == "kei.policy-bundle/v2" && !v.V2ToolRegistered(name)
}

func (e *Evaluator) authorizeV2HarnessTool(ctx context.Context, req Request, connectorID, capability, resource string) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	if req.Session == DefaultSession {
		return Decision{Reason: "v2 harness authorization requires a named session", ReasonCode: "session_required", DenySource: "identity"}, nil
	}
	if live, reason := e.sessionLive(req.Session); !live {
		return sessionDenial(reason), nil
	}
	v, state, err := e.check()
	if err != nil {
		return stateDenial(state), nil
	}
	var subject *policybundle.SessionSubject
	if current, ok := e.sessions.Get(req.Session); ok {
		subject = &policybundle.SessionSubject{UserID: current.UserID, Email: current.Email, Source: current.Source, ExternalID: current.ExternalID, Status: string(current.Status)}
	}
	d := v.EvaluateV2HarnessToolForTarget(req.Tool, req.AgentID, connectorID, capability, resource, subject, e.now().UTC())
	return Decision{Allow: d.Outcome == "allow", Reason: d.Reason, ReasonCode: d.ReasonCode, DenySource: denySource(d.ReasonCode), PolicyID: d.PolicyID, BundleVersion: v.Payload.BundleVersion, BundleDigest: v.Digest, PolicyRevision: v.Payload.PolicyRevision, BundleState: string(state)}, nil
}

// AuthorizeV2Model decides a model call for the subject held by the request's
// session (ADR-035 §6). The calling agent's model-profile assignment in the
// bundle is the permission; nothing is resolved online. v2 is false only when
// the active bundle is valid and not v2, so the caller keeps its v1 path. An
// unusable bundle (missing, expired, revoked, stale) is a v2 denial, because
// no path may permit a model call from it.
func (e *Evaluator) AuthorizeV2Model(ctx context.Context, sessionID, agentID, profileID string) (d Decision, v2 bool, err error) {
	if err := ctx.Err(); err != nil {
		return Decision{}, true, err
	}
	if live, reason := e.sessionLive(sessionID); !live {
		return sessionDenial(reason), true, nil
	}
	v, state, err := e.check()
	if err != nil {
		return stateDenial(state), true, nil
	}
	if v.Payload.Schema != "kei.policy-bundle/v2" {
		return Decision{}, false, nil
	}
	var subject *policybundle.SessionSubject
	if e.sessions != nil {
		if current, ok := e.sessions.Get(sessionID); ok {
			subject = &policybundle.SessionSubject{UserID: current.UserID, Email: current.Email, Source: current.Source, ExternalID: current.ExternalID, Status: string(current.Status)}
		}
	}
	m := v.EvaluateV2Model(profileID, agentID, subject, e.now().UTC())
	return Decision{Allow: m.Outcome == "allow", Reason: m.Reason, ReasonCode: m.ReasonCode, DenySource: denySource(m.ReasonCode), BundleVersion: v.Payload.BundleVersion, BundleDigest: v.Digest, PolicyRevision: v.Payload.PolicyRevision, BundleState: string(state)}, true, nil
}

// ReconcileSession is the compatibility wrapper for callers that ignore revoked ids.
func (e *Evaluator) ReconcileSession() { e.ReconcileSessions() }
func (e *Evaluator) ReconcileSessions() []string {
	if e.sessions == nil {
		return nil
	}
	v, _, err := e.check()
	if err != nil {
		if errors.Is(err, policybundle.ErrSubjectSnapshotStale) {
			return e.sessions.revokeIf(func(sub Subject) bool { return sub.Status == StatusLinked })
		}
		return nil
	}
	now := e.now().UTC()
	m := e.memberships(v, now)
	return e.sessions.revokeIf(func(sub Subject) bool {
		if sub.Status != StatusLinked {
			return false
		}
		if sub.Source == "installation_owner" {
			return v.Payload.Subject == nil || v.Payload.Subject.UserID != sub.UserID
		}
		if v.Payload.SubjectResolution.Mode == "bundle" {
			id, found := v.LookupIdentity(sub.Source, sub.ExternalID, now)
			if sub.Source == "" || sub.ExternalID == "" || !found || id.UserID != sub.UserID || id.Status != policybundle.SubjectLinked {
				return true
			}
		}
		if m == nil {
			return v.Payload.SubjectResolution.Mode == "bundle"
		}
		_, _, granted, known := m.Lookup(sub.UserID)
		return (known && !granted) || (v.Payload.SubjectResolution.Mode == "bundle" && (!known || !granted))
	})
}

// RevokeSession revokes every session because the installation was revoked.
func (e *Evaluator) RevokeSession() {
	if e.sessions != nil {
		e.sessions.revoke()
	}
}

// ResolveBundleIdentity looks up one external identity in the current verified
// local bundle. It performs no control-plane request and rejects stale bundle
// state, non-bundle mode, duplicate matches, and expired identities.
func (e *Evaluator) ResolveBundleIdentity(source, externalID string) (policybundle.Identity, bool) {
	v, _, err := e.check()
	if err != nil {
		return policybundle.Identity{}, false
	}
	return v.LookupIdentity(source, externalID, e.now().UTC())
}

// LookupLinkedUser resolves one fresh linked identity by user ID. The identity
// may carry a subject token used only by the daemon's credential store.
func (e *Evaluator) LookupLinkedUser(userID string) (policybundle.Identity, bool) {
	v, _, err := e.check()
	if err != nil {
		return policybundle.Identity{}, false
	}
	return v.LookupLinkedUser(userID, e.now().UTC())
}

// BundleServicePrincipalIdentity resolves a principal only from the current
// verified bundle and only for the agent named by its binding projection.
func (e *Evaluator) BundleServicePrincipalIdentity(id, agentID string) (policybundle.ServicePrincipalIdentity, bool) {
	return e.lookupBundleServicePrincipalIdentity(func(candidate policybundle.ServicePrincipalIdentity) bool {
		return candidate.ServicePrincipalID == id
	}, agentID)
}

// BundleServicePrincipalIdentityByName resolves exactly one named principal
// from the current bundle for the trusted agent.
func (e *Evaluator) BundleServicePrincipalIdentityByName(name, agentID string) (policybundle.ServicePrincipalIdentity, bool) {
	return e.lookupBundleServicePrincipalIdentity(func(candidate policybundle.ServicePrincipalIdentity) bool {
		return candidate.ServicePrincipalName == name
	}, agentID)
}

func (e *Evaluator) lookupBundleServicePrincipalIdentity(matches func(policybundle.ServicePrincipalIdentity) bool, agentID string) (policybundle.ServicePrincipalIdentity, bool) {
	v, _, err := e.check()
	if err != nil || v.Payload.Schema != "kei.policy-bundle/v2" || !v.SubjectSnapshotFresh(e.now().UTC()) {
		return policybundle.ServicePrincipalIdentity{}, false
	}
	var found *policybundle.ServicePrincipalIdentity
	for i := range v.Payload.ServicePrincipalIdentities {
		candidate := &v.Payload.ServicePrincipalIdentities[i]
		if candidate.AgentID != agentID || candidate.SubjectType != "service_principal" || !matches(*candidate) {
			continue
		}
		if found != nil {
			return policybundle.ServicePrincipalIdentity{}, false
		}
		found = candidate
	}
	if found == nil || !e.now().UTC().Before(found.ExpireTime) {
		return policybundle.ServicePrincipalIdentity{}, false
	}
	out := *found
	out.Groups = append([]string(nil), found.Groups...)
	return out, true
}

// BundleIdentities returns the identities from the current verified bundle,
// or nil when the bundle is missing, invalid, expired, or has no identities.
func (e *Evaluator) BundleIdentities() []policybundle.Identity {
	v, _, err := e.check()
	if err != nil {
		return nil
	}
	return v.Payload.Identities
}

// BundleInstallationSubject returns the current verified v2 installation subject.
// The returned subject is copied so callers cannot mutate the verified payload.
func (e *Evaluator) BundleInstallationSubject() (*policybundle.InstallationSubject, bool) {
	v, _, err := e.check()
	if err != nil || v.Payload.Schema != "kei.policy-bundle/v2" || v.Payload.Subject == nil || v.Payload.Subject.UserID == "" {
		return nil, false
	}
	subject := *v.Payload.Subject
	subject.Groups = append([]string(nil), subject.Groups...)
	return &subject, true
}

// BundleStatus reports the locally stored bundle schema and state without
// contacting the control plane. Schema is retained for invalid/expired bundles
// when it can be safely read from the stored document.
func (e *Evaluator) BundleStatus() (policybundle.Status, error) {
	return e.store.Status(e.now().UTC())
}

// IsV2HarnessTool reports whether name has an explicit harness_executor route
// in the current verified v2 bundle. It performs no network request.
func (e *Evaluator) IsV2HarnessTool(name string) bool {
	v, _, err := e.check()
	return err == nil && v.V2HarnessTool(name, e.now().UTC())
}

// Bundle returns the verified bundle in force, or false when none is valid.
func (e *Evaluator) Bundle() (*policybundle.Verified, bool) {
	v, _, err := e.check()
	return v, err == nil && v != nil
}

func (e *Evaluator) check() (*policybundle.Verified, policybundle.State, error) {
	return e.store.Check(e.aud.InstallationID, e.aud.OrgID, e.aud.WorkspaceID, e.now().UTC())
}

func stateDenial(state policybundle.State) Decision {
	code := "policy_bundle_missing"
	switch state {
	case policybundle.Expired:
		code = "policy_bundle_expired"
	case policybundle.Stale:
		code = "subject_snapshot_stale"
	case policybundle.Invalid:
		code = "policy_bundle_invalid"
	case policybundle.Unsupported:
		code = "policy_bundle_unsupported"
	case policybundle.Revoked:
		code = "installation_revoked"
	}
	if state == "" {
		state = policybundle.Cold
	}
	return Decision{Reason: "no valid local policy bundle", ReasonCode: code, DenySource: "runtime_state", BundleState: string(state)}
}

func denySource(code string) string {
	switch {
	case code == "":
		return ""
	case strings.HasPrefix(code, "policy_bundle_"), code == "installation_revoked", code == "startup_config_invalid":
		return "runtime_state"
	case strings.HasPrefix(code, "tool_"), strings.HasPrefix(code, "agent_"), strings.HasPrefix(code, "model_"):
		return "registry"
	case strings.HasPrefix(code, "subject_"), code == ReasonSessionNotFound, code == "session_required":
		return "identity"
	}
	return "policy"
}
