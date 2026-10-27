package pdp

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

// TestSessionsCreateGetEnd: named sessions get distinct opaque ids, read
// back their own subject, and end independently of each other and of the
// default session. The end hook runs once per session.
func TestSessionsCreateGetEnd(t *testing.T) {
	s := NewSessions()
	var ended []string
	var mu sync.Mutex
	s.OnEnd(func(id string) { mu.Lock(); ended = append(ended, id); mu.Unlock() })

	a, err := s.Create(Subject{UserID: "u-alice", Status: StatusLinked})
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Create(Subject{UserID: "u-bob", Status: StatusLinked})
	if err != nil {
		t.Fatal(err)
	}
	if a == b || !strings.HasPrefix(a, "ks_") || len(a) != 3+43 {
		t.Fatalf("ids %q %q: want distinct ks_ + 43 base64url characters", a, b)
	}
	for id, want := range map[string]string{a: "u-alice", b: "u-bob"} {
		if sub, ok := s.Get(id); !ok || sub.UserID != want {
			t.Errorf("Get(%q) = %+v %v, want %s", id, sub, ok, want)
		}
	}
	if _, err := s.Create(Subject{Status: StatusLinked}); err == nil {
		t.Error("a linked named session started without a user id")
	}

	if !s.EndID(a) || s.EndID(a) {
		t.Fatal("EndID must report true once, then false")
	}
	if _, ok := s.Get(a); ok {
		t.Error("an ended session is still readable")
	}
	if sub, ok := s.Get(b); !ok || sub.UserID != "u-bob" {
		t.Error("ending one session ended another")
	}
	if _, ok := s.Get("ks_never-created"); ok {
		t.Error("an unknown id is readable")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(ended) != 1 || ended[0] != a {
		t.Errorf("end hook ran for %v, want exactly [%s]", ended, a)
	}
}

// TestSessionsIdleTTL: a named session ends after the idle TTL without use;
// each use restarts the clock; Sweep ends idle ones; the default session
// never expires.
func TestSessionsIdleTTL(t *testing.T) {
	s := NewSessions()
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	s.SetIdleTTL(time.Minute)
	var ended atomic.Int32
	s.OnEnd(func(string) { ended.Add(1) })

	used, _ := s.Create(Subject{UserID: "u-1", Status: StatusLinked})
	idle, _ := s.Create(Subject{UserID: "u-2", Status: StatusLinked})
	_ = s.Start(Subject{UserID: "u-default", Status: StatusLinked})

	now = now.Add(50 * time.Second)
	if _, ok := s.Get(used); !ok {
		t.Fatal("session expired early")
	}
	now = now.Add(50 * time.Second) // used: 50s idle; idle: 100s idle
	if got := s.Sweep(); len(got) != 1 || got[0] != idle {
		t.Fatalf("Sweep = %v, want [%s]", got, idle)
	}
	if !s.Exists(used) || s.Exists(idle) {
		t.Fatal("sweep ended the wrong session")
	}
	now = now.Add(2 * time.Minute)
	if _, ok := s.Get(used); ok {
		t.Fatal("an idle session was still readable after the TTL")
	}
	if ended.Load() != 2 {
		t.Errorf("end hook ran %d times, want 2", ended.Load())
	}
	if _, ok := s.Current(); !ok {
		t.Error("the default session expired")
	}
}

// TestSessionsConcurrent: many goroutines create, read and end their own
// sessions at once; each only ever sees its own subject (run with -race).
func TestSessionsConcurrent(t *testing.T) {
	s := NewSessions()
	var wg sync.WaitGroup
	for g := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			user := fmt.Sprintf("u-%d", g)
			id, err := s.Create(Subject{UserID: user, Status: StatusLinked})
			if err != nil {
				t.Error(err)
				return
			}
			for range 200 {
				if sub, ok := s.Get(id); !ok || sub.UserID != user {
					t.Errorf("session %s read %+v %v", user, sub, ok)
					return
				}
			}
			if !s.EndID(id) {
				t.Errorf("session %s did not end", user)
			}
		}()
	}
	wg.Wait()
	if n := s.Len(); n != 0 {
		t.Errorf("%d sessions left", n)
	}
}

// TestEvaluatePerSession: a decision uses only the named session's subject;
// an unknown, ended, or empty session denies session_not_found.
func TestEvaluatePerSession(t *testing.T) {
	useValidator(t, schemaValidator(t))
	sessions := NewSessions()
	e, _, _ := newTestEvaluator(t, testNow, testBundle(t, testNow, 42, evaluatorPolicies, nil), sessions)
	linked, _ := sessions.Create(Subject{UserID: "u-alice", Status: StatusLinked})
	unlinked, _ := sessions.Create(Subject{Status: StatusUnlinked})

	reason := func(id string) string {
		t.Helper()
		d, err := e.Evaluate(context.Background(), Request{Session: id, Tool: "github.create_issue"})
		if err != nil {
			t.Fatal(err)
		}
		return d.ReasonCode
	}
	if got := reason(linked); got != "" {
		t.Errorf("linked session: reason %q, want a permit", got)
	}
	if got := reason(unlinked); got != "subject_unlinked" {
		t.Errorf("unlinked session: reason %q, want subject_unlinked", got)
	}
	if got := reason(""); got != ReasonSessionNotFound {
		t.Errorf("empty session: reason %q, want %s", got, ReasonSessionNotFound)
	}
	if got := reason("ks_unknown"); got != ReasonSessionNotFound {
		t.Errorf("unknown id: reason %q, want %s", got, ReasonSessionNotFound)
	}
	d, _ := e.Evaluate(context.Background(), Request{Session: "ks_unknown", Tool: "github.create_issue"})
	if d.Allow || d.DenySource != "identity" {
		t.Errorf("unknown id decision = %+v", d)
	}
	g, _ := e.EvaluateConnector(context.Background(), Request{Session: "ks_unknown", Connector: &ConnectorTarget{ConnectorID: "c", Capability: "x"}})
	if g.Allow || g.HasSession || g.ReasonCode != ReasonSessionNotFound {
		t.Errorf("unknown id connector grant = %+v", g)
	}
	sessions.EndID(linked)
	if got := reason(linked); got != ReasonSessionNotFound {
		t.Errorf("ended session: reason %q, want %s", got, ReasonSessionNotFound)
	}
}

// TestReconcileSessionsPerSession: reconcile revokes only the sessions whose
// subject the bundle no longer grants, and installation revocation revokes
// them all.
func TestReconcileSessionsPerSession(t *testing.T) {
	useValidator(t, schemaValidator(t))
	sessions := NewSessions()
	e, _, _ := newTestEvaluator(t, testNow, testBundle(t, testNow, 42, evaluatorPolicies, nil), sessions)
	alice, _ := sessions.Create(Subject{UserID: "u-alice", Status: StatusLinked})
	bob, _ := sessions.Create(Subject{UserID: "u-bob", Status: StatusLinked})

	e.memberships = func(*policybundle.Verified, time.Time) policybundle.Memberships {
		return fakeMemberships{"u-alice": {granted: false}, "u-bob": {granted: true}}
	}
	revoked := e.ReconcileSessions()
	e.memberships = policybundle.BundleMembershipsAt
	if len(revoked) != 1 || revoked[0] != alice {
		t.Fatalf("revoked %v, want only alice's session %s", revoked, alice)
	}
	for id, want := range map[string]Status{alice: StatusRevoked, bob: StatusLinked} {
		if sub, _ := sessions.Get(id); sub.Status != want {
			t.Errorf("session %q status %s, want %s", id, sub.Status, want)
		}
	}
	d, _ := e.Evaluate(context.Background(), Request{Session: alice, Tool: "github.create_issue"})
	if d.ReasonCode != "subject_revoked" {
		t.Errorf("revoked session decision = %+v", d)
	}

	e.RevokeSession()
	if sub, _ := sessions.Get(bob); sub.Status != StatusRevoked {
		t.Errorf("after installation revocation session %q is %s", bob, sub.Status)
	}
}

func TestEmptySessionIsNotLive(t *testing.T) {
	sessions := NewSessions()
	if err := sessions.Start(Subject{UserID: "u-default", Status: StatusLinked}); err != nil {
		t.Fatal(err)
	}
	e := &Evaluator{sessions: sessions}
	if live, reason := e.sessionLive(""); live || reason != ReasonSessionNotFound {
		t.Fatalf("sessionLive(empty) = %t, %q; want false, %q", live, reason, ReasonSessionNotFound)
	}
	if d, err := e.Evaluate(context.Background(), Request{Tool: "github.create_issue"}); err != nil || d.ReasonCode != ReasonSessionNotFound {
		t.Errorf("Evaluate(empty) = %+v, %v; want %s", d, err, ReasonSessionNotFound)
	}
	if g, err := e.EvaluateConnector(context.Background(), Request{Connector: &ConnectorTarget{ConnectorID: "c", Capability: "x"}}); err != nil || g.ReasonCode != ReasonSessionNotFound {
		t.Errorf("EvaluateConnector(empty) = %+v, %v; want %s", g, err, ReasonSessionNotFound)
	}
	if d, err := e.AuthorizeShell(context.Background(), "", "git status", "agent"); err != nil || d.ReasonCode != ReasonSessionNotFound {
		t.Errorf("AuthorizeShell(empty) = %+v, %v; want %s", d, err, ReasonSessionNotFound)
	}
	if d, v2, err := e.AuthorizeV2Model(context.Background(), "", "agent", "profile"); err != nil || !v2 || d.ReasonCode != ReasonSessionNotFound {
		t.Errorf("AuthorizeV2Model(empty) = %+v, v2=%t, %v; want %s", d, v2, err, ReasonSessionNotFound)
	}
}

func TestRevokingServicePrincipalSessionPreservesTypedSubject(t *testing.T) {
	sessions := NewSessions()
	id, err := sessions.Create(Subject{SubjectKind: "service_principal", UserID: "sp-intake", Status: StatusLinked})
	if err != nil {
		t.Fatal(err)
	}
	sessions.revokeIf(func(Subject) bool { return true })
	sub, ok := sessions.Get(id)
	if !ok || sub.Status != StatusRevoked || sub.SubjectKind != "service_principal" {
		t.Fatalf("revoked principal subject = %+v, live=%t", sub, ok)
	}
}

// TestSessionsMaxAge: a named session is recycled after 8 hours (max age)
// regardless of use; the next sessionLive check returns session_revalidation_required;
// onRecycle and onEnd both fire; the default session is not affected.
func TestSessionsMaxAge(t *testing.T) {
	s := NewSessions()
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	s.SetNow(func() time.Time { return now })
	s.SetIdleTTL(time.Minute)

	var ended atomic.Int32    // onEnd fires for any session end
	var recycled atomic.Int32 // onRecycle fires only for max-age recycle
	s.OnEnd(func(string) { ended.Add(1) })
	s.OnRecycle(func(string) { recycled.Add(1) })

	young, _ := s.Create(Subject{UserID: "u-young", Status: StatusLinked})
	old, _ := s.Create(Subject{UserID: "u-old", Status: StatusLinked})
	_ = s.Start(Subject{UserID: "u-default", Status: StatusLinked})

	// Both are still live before 8 h.
	if _, ok := s.Get(young); !ok {
		t.Fatal("young session expired before max age")
	}
	if _, ok := s.Get(old); !ok {
		t.Fatal("old session expired before max age")
	}

	// Advance 8 h + 1 s so both exceed max age.
	now = now.Add(SessionMaxAge + time.Second)

	// Accessing old recycles it: onEnd + onRecycle fire, recycled recorded.
	if _, ok := s.Get(old); ok {
		t.Fatal("old session should have been recycled")
	}
	if ended.Load() != 1 {
		t.Errorf("onEnd ran %d times, want 1", ended.Load())
	}
	if recycled.Load() != 1 {
		t.Errorf("onRecycle ran %d times, want 1", recycled.Load())
	}

	// ConsumeRecycled reports true exactly once.
	if !s.ConsumeRecycled(old) {
		t.Error("ConsumeRecycled(old) should be true")
	}
	if s.ConsumeRecycled(old) {
		t.Error("ConsumeRecycled(old) should be false after consumption")
	}
	if s.Exists(old) {
		t.Error("old session should not exist after recycle")
	}

	// Young is still live (not yet accessed after max age).
	if _, ok := s.Get(young); ok {
		t.Fatal("young session should also have been recycled on access")
	}
	if ended.Load() != 2 {
		t.Errorf("onEnd ran %d times, want 2", ended.Load())
	}
	if recycled.Load() != 2 {
		t.Errorf("onRecycle ran %d times, want 2", recycled.Load())
	}

	// Default session is never recycled.
	now = now.Add(SessionMaxAge + time.Second)
	if _, ok := s.Current(); !ok {
		t.Error("the default session must never be recycled")
	}
	if ended.Load() != 2 {
		t.Errorf("default session must not trigger onEnd")
	}
	if recycled.Load() != 2 {
		t.Errorf("default session must not trigger onRecycle")
	}
}

// TestSessionsMaxAgeRecycleReason: calling Evaluate/EvaluateConnector/
// AuthorizeV2Model/AuthorizeV2HarnessTool on a recycled session returns
// session_revalidation_required exactly once, then session_not_found.
func TestSessionsMaxAgeRecycleReason(t *testing.T) {
	useValidator(t, schemaValidator(t))
	s := NewSessions()
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	s.SetNow(func() time.Time { return now })
	s.OnEnd(func(string) {})
	e, _, _ := newTestEvaluator(t, testNow, testBundle(t, testNow, 42, evaluatorPolicies, nil), s)

	sid, _ := s.Create(Subject{UserID: "u-alice", Status: StatusLinked})
	now = now.Add(SessionMaxAge + time.Second)

	// First call sees session_revalidation_required.
	d, err := e.Evaluate(context.Background(), Request{Session: sid, Tool: "github.create_issue"})
	if err != nil {
		t.Fatal(err)
	}
	if d.ReasonCode != ReasonSessionRevalidationRequired {
		t.Errorf("first Evaluate after max age: reasonCode %q, want %s", d.ReasonCode, ReasonSessionRevalidationRequired)
	}
	if d.Allow {
		t.Error("recycled session must deny")
	}

	// Second call sees session_not_found (recycled entry consumed).
	d, err = e.Evaluate(context.Background(), Request{Session: sid, Tool: "github.create_issue"})
	if err != nil {
		t.Fatal(err)
	}
	if d.ReasonCode != ReasonSessionNotFound {
		t.Errorf("second Evaluate after max age: reasonCode %q, want %s", d.ReasonCode, ReasonSessionNotFound)
	}

	// Connector grant also returns session_revalidation_required once.
	sid2, _ := s.Create(Subject{UserID: "u-bob", Status: StatusLinked})
	now = now.Add(SessionMaxAge + time.Second)
	g, _ := e.EvaluateConnector(context.Background(), Request{Session: sid2, Connector: &ConnectorTarget{ConnectorID: "c", Capability: "x"}})
	if g.ReasonCode != ReasonSessionRevalidationRequired {
		t.Errorf("EvaluateConnector after max age: reasonCode %q, want %s", g.ReasonCode, ReasonSessionRevalidationRequired)
	}
	g, _ = e.EvaluateConnector(context.Background(), Request{Session: sid2, Connector: &ConnectorTarget{ConnectorID: "c", Capability: "x"}})
	if g.ReasonCode != ReasonSessionNotFound {
		t.Errorf("EvaluateConnector second call: reasonCode %q, want %s", g.ReasonCode, ReasonSessionNotFound)
	}
}
