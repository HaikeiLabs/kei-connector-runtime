package runtime

import (
	"errors"
	"sync"
	"testing"
	"time"
)

type plannerFunc func([]byte, BindingContext) ([]Operation, error)

func (f plannerFunc) Plan(b []byte, c BindingContext) ([]Operation, error) { return f(b, c) }

type planAuthorizerFunc func(BindingContext, []Operation) (string, int64, bool, error)

func (f planAuthorizerFunc) AuthorizePlan(b BindingContext, ops []Operation) (string, int64, bool, error) {
	return f(b, ops)
}

func testBinding() BindingContext {
	return BindingContext{InstallationID: "i", BundleVersion: 2, BundleDigest: "sha256:bundle", Subject: "u", SubjectSource: "discord", SubjectExternalID: "ext", AgentID: "a", Tool: "t", Route: ConnectorDispatch{ConnectorID: "c", RequiredCapabilities: []string{"read", "meta.read"}}}
}
func testPlan() []Operation {
	return []Operation{{ConnectorID: "c", Capability: "read", Action: "read", ResourceType: "repo", ResourceID: "x"}, {ConnectorID: "c", Capability: "meta.read", Action: "read", ResourceType: "repo", ResourceID: "x"}}
}
func testPreflightInput(allow bool) PreflightInput {
	return PreflightInput{Binding: testBinding(), ValidatedArgs: []byte(`{"id":"x"}`), Planner: plannerFunc(func([]byte, BindingContext) ([]Operation, error) { return testPlan(), nil }), Authorizer: planAuthorizerFunc(func(b BindingContext, ops []Operation) (string, int64, bool, error) {
		return b.BundleDigest, b.BundleVersion, allow, nil
	})}
}

func TestPreflightAndConsumeEachPlanItemOnce(t *testing.T) {
	s := NewAuthorizationStore()
	in := testPreflightInput(true)
	grant, err := s.Preflight(in, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range testPlan() {
		if err = s.Consume(grant.Handle, in.Binding, op, in.Authorizer); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.Consume(grant.Handle, in.Binding, testPlan()[0], in.Authorizer); !errors.Is(err, ErrAuthorizationInvalid) {
		t.Fatalf("replay=%v", err)
	}
}
func TestPreflightRequiresCompleteAndAuthorizedPlan(t *testing.T) {
	for name, plan := range map[string][]Operation{"missing": nil, "extra": append(testPlan(), Operation{ConnectorID: "c", Capability: "secret", Action: "read"}), "missing required": testPlan()[:1]} {
		t.Run(name, func(t *testing.T) {
			in := testPreflightInput(true)
			in.Planner = plannerFunc(func([]byte, BindingContext) ([]Operation, error) { return plan, nil })
			if _, err := NewAuthorizationStore().Preflight(in, time.Second); err == nil {
				t.Fatal("invalid plan accepted")
			}
		})
	}
	if _, err := NewAuthorizationStore().Preflight(testPreflightInput(false), time.Second); err == nil {
		t.Fatal("denied PDP plan accepted")
	}
}
func TestConsumeRevalidatesPlanAndRejectsSubstitutionAndExpiry(t *testing.T) {
	s := NewAuthorizationStore()
	now := time.Now()
	s.now = func() time.Time { return now }
	in := testPreflightInput(true)
	grant, err := s.Preflight(in, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	changed := in.Binding
	changed.SubjectExternalID = "other"
	if err = s.Consume(grant.Handle, changed, testPlan()[0], in.Authorizer); !errors.Is(err, ErrAuthorizationInvalid) {
		t.Fatalf("identity substitution=%v", err)
	}
	deny := planAuthorizerFunc(func(BindingContext, []Operation) (string, int64, bool, error) { return "", 0, false, nil })
	if err = s.Consume(grant.Handle, in.Binding, testPlan()[0], deny); !errors.Is(err, ErrAuthorizationInvalid) {
		t.Fatalf("changed authorization=%v", err)
	}
	grant, err = s.Preflight(in, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if err = s.Consume(grant.Handle, in.Binding, testPlan()[0], in.Authorizer); !errors.Is(err, ErrAuthorizationInvalid) {
		t.Fatalf("expired=%v", err)
	}
}
func TestAuthorizationConsumeIsAtomic(t *testing.T) {
	s := NewAuthorizationStore()
	in := testPreflightInput(true)
	grant, err := s.Preflight(in, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	accepted := 0
	var mu sync.Mutex
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.Consume(grant.Handle, in.Binding, testPlan()[0], in.Authorizer) == nil {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if accepted != 1 {
		t.Fatalf("accepted %d consumers", accepted)
	}
}
func TestInvalidationDropsOutstandingHandles(t *testing.T) {
	s := NewAuthorizationStore()
	in := testPreflightInput(true)
	grant, err := s.Preflight(in, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	s.Invalidate()
	if err = s.Consume(grant.Handle, in.Binding, testPlan()[0], in.Authorizer); !errors.Is(err, ErrAuthorizationInvalid) {
		t.Fatalf("after invalidation=%v", err)
	}
}
