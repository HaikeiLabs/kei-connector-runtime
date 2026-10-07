package pdp

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
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
	if err := s.Start(Subject{UserID: "u-default", Status: StatusLinked}); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{a: "u-alice", b: "u-bob", DefaultSession: "u-default"} {
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
	if sub, ok := s.Current(); !ok || sub.UserID != "u-default" {
		t.Error("ending a named session ended the default session")
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
// an unknown or ended id denies session_not_found, and requests without an id
// use the default session.
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
	if got := reason(DefaultSession); got != "subject_unlinked" {
		t.Errorf("no default session: reason %q, want subject_unlinked", got)
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
	_ = sessions.Start(Subject{UserID: "u-bob", Status: StatusLinked})

	e.memberships = func(*policybundle.Verified, time.Time) policybundle.Memberships {
		return fakeMemberships{"u-alice": {granted: false}, "u-bob": {granted: true}}
	}
	revoked := e.ReconcileSessions()
	e.memberships = policybundle.BundleMembershipsAt
	if len(revoked) != 1 || revoked[0] != alice {
		t.Fatalf("revoked %v, want only alice's session %s", revoked, alice)
	}
	for id, want := range map[string]Status{alice: StatusRevoked, bob: StatusLinked, DefaultSession: StatusLinked} {
		if sub, _ := sessions.Get(id); sub.Status != want {
			t.Errorf("session %q status %s, want %s", id, sub.Status, want)
		}
	}
	d, _ := e.Evaluate(context.Background(), Request{Session: alice, Tool: "github.create_issue"})
	if d.ReasonCode != "subject_revoked" {
		t.Errorf("revoked session decision = %+v", d)
	}

	e.RevokeSession()
	for _, id := range []string{bob, DefaultSession} {
		if sub, _ := sessions.Get(id); sub.Status != StatusRevoked {
			t.Errorf("after installation revocation session %q is %s", id, sub.Status)
		}
	}
}
