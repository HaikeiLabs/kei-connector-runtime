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

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
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
// comes only from the in-memory session.
type Request struct {
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
	memberships func(*policybundle.Verified) policybundle.Memberships
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
	return &Evaluator{store: store, aud: aud, sessions: sessions, now: time.Now, memberships: policybundle.BundleMemberships}, nil
}

// Evaluate decides one call. The error is non-nil only when ctx is done.
func (e *Evaluator) Evaluate(ctx context.Context, req Request) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	v, state, err := e.check()
	if err != nil {
		return stateDenial(state), nil
	}
	call := policybundle.Call{Tool: req.Tool, Action: req.Action, Resource: req.Resource, AgentID: req.AgentID}
	if req.Connector != nil {
		call.ConnectorID, call.Capability, call.ConnectorInvocation = req.Connector.ConnectorID, req.Connector.Capability, true
	}
	var subject *policybundle.SessionSubject
	var current Subject
	if e.sessions != nil {
		var ok bool
		if current, ok = e.sessions.Current(); ok {
			subject = &policybundle.SessionSubject{UserID: current.UserID, Email: current.Email, Status: string(current.Status)}
		}
	}
	d := v.EvaluateSession(call, subject, e.memberships(v))
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
	return out, nil
}

// AuthorizeOperation implements runtime.OperationAuthorizer without importing
// runtime (which depends on this package). Callers provide trusted identity
// fields and an exact planner-produced operation.
func (e *Evaluator) AuthorizeOperation(installationID, subjectID, agentID, tool string, op policybundle.Operation) (string, bool, error) {
	if installationID != e.aud.InstallationID || subjectID == "" || tool == "" {
		return "", false, nil
	}
	if e.sessions == nil {
		return "", false, nil
	}
	current, ok := e.sessions.Current()
	if !ok || current.UserID != subjectID {
		return "", false, nil
	}
	d, err := e.Evaluate(context.Background(), Request{Tool: tool, AgentID: agentID, Action: op.Action, Resource: op.Resource, Connector: &ConnectorTarget{ConnectorID: op.ConnectorID, Capability: op.Capability}})
	return d.BundleDigest, err == nil && d.Allow, err
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

// ReconcileSession ends the session of a subject the active bundle no longer
// grants (ADR-026 G0: revocation takes effect at the next refresh). The
// refresher calls it after every refresh.
func (e *Evaluator) ReconcileSession() {
	if e.sessions == nil {
		return
	}
	current, ok := e.sessions.Current()
	if !ok || current.Status != StatusLinked {
		return
	}
	v, _, err := e.check()
	if err != nil {
		return
	}
	m := e.memberships(v)
	if m == nil {
		return
	}
	if _, _, granted, known := m.Lookup(current.UserID); known && !granted {
		e.sessions.revoke()
	}
}

// RevokeSession ends the session because the installation was revoked.
func (e *Evaluator) RevokeSession() {
	if e.sessions != nil {
		e.sessions.revoke()
	}
}

func (e *Evaluator) check() (*policybundle.Verified, policybundle.State, error) {
	return e.store.Check(e.aud.InstallationID, e.aud.OrgID, e.aud.WorkspaceID, e.now().UTC())
}

func stateDenial(state policybundle.State) Decision {
	code := "policy_bundle_missing"
	switch state {
	case policybundle.Expired:
		code = "policy_bundle_expired"
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
	case strings.HasPrefix(code, "tool_"), strings.HasPrefix(code, "agent_"):
		return "registry"
	case strings.HasPrefix(code, "subject_"):
		return "identity"
	}
	return "policy"
}
