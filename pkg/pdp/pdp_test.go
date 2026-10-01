package pdp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

var testNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

var evaluatorPolicies = []testPolicy{
	{ID: "pol-1", Src: "*", Dst: "github:admin", Action: "deny"},
	{ID: "pol-2", Src: "user:u-alice", Dst: "github:write", Action: "permit"},
	{ID: "pol-3", Src: "group:members", Dst: "tool:search_wiki", Action: "permit"},
	{ID: "pol-4", Src: "agent:" + testAgent, Dst: "capability:issue.create", Action: "permit", AgentID: testAgent},
	{ID: "pol-5", Src: "*", Dst: "tool:search_web", Action: "permit"},
}

func TestEvaluate(t *testing.T) {
	useValidator(t, schemaValidator(t))
	onlyGetBound := []map[string]any{{"agent_id": testAgent, "connector_id": "conn-github-0001", "capabilities": []string{"issue.get"}}}
	alice := &Subject{UserID: "u-alice", Status: StatusLinked}
	bob := &Subject{UserID: "u-bob", Status: StatusLinked}
	enrollment := json.RawMessage(`{"provider":"teams","url":"https://example.invalid/link"}`)
	cases := []struct {
		name       string
		req        Request
		session    *Subject
		members    policybundle.Memberships
		allow      bool
		reasonCode string
		denySource string
		policyID   string
		enrollment bool
	}{
		{name: "agent-only permit with no session", req: Request{Tool: "search_web"}, allow: true, policyID: "pol-5"},
		{name: "matching deny policy", req: Request{Tool: "github.delete_repo"}, reasonCode: "policy_deny", denySource: "policy", policyID: "pol-1"},
		{name: "deny policy wins for a linked subject", req: Request{Tool: "github.delete_repo"}, session: alice, reasonCode: "policy_deny", denySource: "policy", policyID: "pol-1"},
		{name: "default deny when nothing matches", req: Request{Tool: "github.get_issue"}, reasonCode: "no_matching_policy", denySource: "policy"},
		{name: "unknown tool", req: Request{Tool: "shell.exec"}, reasonCode: "tool_not_registered", denySource: "registry"},
		{name: "caller action differs from registry", req: Request{Tool: "github.get_issue", Action: "github:write"}, reasonCode: "tool_action_mismatch", denySource: "registry"},
		{name: "agent not assigned", req: Request{Tool: "search_web", AgentID: "agent-other"}, reasonCode: "agent_not_assigned", denySource: "registry"},
		{name: "connector capability permit", req: Request{Connector: &ConnectorTarget{ConnectorID: "conn-github-0001", Capability: "issue.create"}}, allow: true, policyID: "pol-4"},
		{name: "connector capability not registered", req: Request{Connector: &ConnectorTarget{ConnectorID: "conn-github-0001", Capability: "issue.close"}}, reasonCode: "tool_not_registered", denySource: "registry"},
		{name: "human policy with no session denies unlinked", req: Request{Tool: "github.create_issue"}, reasonCode: "subject_unlinked", denySource: "identity"},
		{name: "linked user permit", req: Request{Tool: "github.create_issue"}, session: alice, allow: true, policyID: "pol-2"},
		{name: "another user's policy falls through to the agent permit", req: Request{Tool: "github.create_issue"}, session: bob, allow: true, policyID: "pol-4"},
		{name: "linked user with no matching policy", req: Request{Tool: "github.get_issue"}, session: bob, reasonCode: "no_matching_policy", denySource: "policy"},
		{name: "group source without bundle memberships fails closed", req: Request{Tool: "search_wiki"}, session: alice, reasonCode: "subject_pending", denySource: "identity"},
		{name: "group source with memberships permits", req: Request{Tool: "search_wiki"}, session: bob, members: fakeMemberships{"u-bob": {groups: []string{"members"}, granted: true}}, allow: true, policyID: "pol-3"},
		{name: "subject the bundle no longer grants", req: Request{Tool: "search_web"}, session: bob, members: fakeMemberships{"u-bob": {granted: false}}, reasonCode: "subject_revoked", denySource: "identity"},
		{name: "unlinked session gets enrollment", req: Request{Tool: "search_web"}, session: &Subject{Status: StatusUnlinked, Enrollment: enrollment}, reasonCode: "subject_unlinked", denySource: "identity", enrollment: true},
		{name: "pending session denies before policy", req: Request{Tool: "search_web"}, session: &Subject{UserID: "u-carol", Status: StatusPending, Enrollment: enrollment}, reasonCode: "subject_pending", denySource: "identity"},
		{name: "cross-workspace session never falls through", req: Request{Tool: "search_web"}, session: &Subject{UserID: "u-dave", Status: StatusCrossWorkspace}, reasonCode: "subject_cross_workspace", denySource: "identity"},
	}
	bundle := testBundle(t, testNow, 42, evaluatorPolicies, nil)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sessions := NewSessions()
			if tc.session != nil {
				if err := sessions.Start(*tc.session); err != nil {
					t.Fatal(err)
				}
			}
			e, _, _ := newTestEvaluator(t, testNow, bundle, sessions)
			if tc.members != nil {
				e.memberships = func(*policybundle.Verified) policybundle.Memberships { return tc.members }
			}
			d, err := e.Evaluate(context.Background(), tc.req)
			if err != nil {
				t.Fatal(err)
			}
			if d.Allow != tc.allow || d.ReasonCode != tc.reasonCode || d.DenySource != tc.denySource || d.PolicyID != tc.policyID {
				t.Fatalf("decision = %+v, want allow=%v reason_code=%q deny_source=%q policy_id=%q", d, tc.allow, tc.reasonCode, tc.denySource, tc.policyID)
			}
			if (len(d.Enrollment) > 0) != tc.enrollment {
				t.Fatalf("enrollment = %s, want present=%v", d.Enrollment, tc.enrollment)
			}
			if d.BundleVersion != 42 || d.PolicyRevision != 17 || d.BundleDigest == "" || d.BundleState != "active" {
				t.Fatalf("decision lacks bundle provenance: %+v", d)
			}
		})
	}
	t.Run("connector capability the agent is not bound to", func(t *testing.T) {
		e, _, _ := newTestEvaluator(t, testNow, testBundle(t, testNow, 42, evaluatorPolicies, onlyGetBound), nil)
		d, _ := e.Evaluate(context.Background(), Request{Connector: &ConnectorTarget{ConnectorID: "conn-github-0001", Capability: "issue.create"}})
		if d.Allow || d.ReasonCode != "agent_not_bound_to_connector" || d.DenySource != "registry" {
			t.Fatalf("decision = %+v", d)
		}
	})
}

func TestEvaluateRuntimeStateDenies(t *testing.T) {
	useValidator(t, schemaValidator(t))
	bundle := testBundle(t, testNow, 42, evaluatorPolicies, nil)
	cases := []struct {
		name, reasonCode, state string
		setup                   func(t *testing.T, e *Evaluator, store *policybundle.Store, dir string)
	}{
		{name: "cold start with no bundle", reasonCode: "policy_bundle_missing", state: "cold", setup: func(*testing.T, *Evaluator, *policybundle.Store, string) {}},
		{name: "bundle past not_after", reasonCode: "policy_bundle_expired", state: "expired", setup: func(t *testing.T, e *Evaluator, s *policybundle.Store, _ string) {
			mustActivate(t, s, bundle)
			e.now = func() time.Time { return testNow.Add(12 * time.Hour) }
		}},
		{name: "tampered persisted bundle", reasonCode: "policy_bundle_invalid", state: "invalid", setup: func(t *testing.T, _ *Evaluator, s *policybundle.Store, dir string) {
			mustActivate(t, s, bundle)
			path := filepath.Join(dir, "policy", "bundle.json")
			b, _ := os.ReadFile(path)
			b[len(b)-1] = ' '
			if err := os.WriteFile(path, append(b, '}'), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "installation revoked", reasonCode: "installation_revoked", state: "revoked", setup: func(t *testing.T, _ *Evaluator, s *policybundle.Store, _ string) {
			mustActivate(t, s, bundle)
			if err := s.Revoke(testNow); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, store, dir := newTestEvaluator(t, testNow, nil, nil)
			tc.setup(t, e, store, dir)
			d, err := e.Evaluate(context.Background(), Request{Tool: "search_web"})
			if err != nil {
				t.Fatal(err)
			}
			if d.Allow || d.ReasonCode != tc.reasonCode || d.DenySource != "runtime_state" || d.BundleState != tc.state || d.PolicyID != "" {
				t.Fatalf("decision = %+v, want deny %s in state %s", d, tc.reasonCode, tc.state)
			}
		})
	}
}

func TestEvaluateRespectsCanceledContext(t *testing.T) {
	useValidator(t, schemaValidator(t))
	e, _, _ := newTestEvaluator(t, testNow, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Evaluate(ctx, Request{Tool: "search_web"}); err == nil {
		t.Fatal("Evaluate ignored a canceled context")
	}
}

func TestSessionLifecycle(t *testing.T) {
	useValidator(t, schemaValidator(t))
	sessions := NewSessions()
	e, _, _ := newTestEvaluator(t, testNow, testBundle(t, testNow, 42, evaluatorPolicies, nil), sessions)
	if err := sessions.Start(Subject{Status: StatusRevoked, UserID: "u-alice"}); err == nil {
		t.Fatal("a caller started a revoked session")
	}
	if err := sessions.Start(Subject{Status: StatusLinked}); err == nil {
		t.Fatal("a linked session started without a user id")
	}
	if err := sessions.Start(Subject{UserID: "u-alice", Status: StatusLinked}); err != nil {
		t.Fatal(err)
	}
	want := func(reasonCode string) {
		t.Helper()
		d, _ := e.Evaluate(context.Background(), Request{Tool: "github.create_issue"})
		if d.ReasonCode != reasonCode {
			t.Fatalf("reason_code = %q, want %q (%+v)", d.ReasonCode, reasonCode, d)
		}
	}
	want("")
	e.ReconcileSession() // a v1 bundle carries no memberships: nothing to revoke
	want("")
	e.memberships = func(*policybundle.Verified) policybundle.Memberships {
		return fakeMemberships{"u-alice": {granted: false}}
	}
	e.ReconcileSession()
	e.memberships = policybundle.BundleMemberships
	want("subject_revoked")
	if err := sessions.Start(Subject{UserID: "u-alice", Status: StatusLinked}); err != nil {
		t.Fatal(err)
	}
	want("")
	sessions.End()
	want("subject_unlinked")
	if err := sessions.Start(Subject{UserID: "u-alice", Status: StatusLinked}); err != nil {
		t.Fatal(err)
	}
	e.RevokeSession()
	want("subject_revoked")
}

func mustActivate(t *testing.T, s *policybundle.Store, bundle []byte) {
	t.Helper()
	if _, err := s.Activate(bundle, testInstallation, testOrg, testWorkspace, testNow); err != nil {
		t.Fatal(err)
	}
}
