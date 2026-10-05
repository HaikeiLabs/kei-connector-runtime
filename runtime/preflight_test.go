package runtime

import (
	"errors"
	"sync"
	"testing"
	"time"
)

type plannerFunc func([]byte, BindingContext) ([]Operation, error)

func (f plannerFunc) Plan(b []byte, c BindingContext) ([]Operation, error) { return f(b, c) }

type authorizerFunc func(string, string, string, string, Operation) (string, bool, error)

func (f authorizerFunc) AuthorizeOperation(i, s, a, t string, o Operation) (string, bool, error) {
	return f(i, s, a, t, o)
}

func testBinding() BindingContext {
	return BindingContext{InstallationID: "i", BundleDigest: "sha256:bundle", Subject: "u", AgentID: "a", Tool: "t", Route: ConnectorDispatch{ConnectorID: "c", RequiredCapabilities: []string{"read"}}}
}
func testPlan() []Operation {
	return []Operation{{ConnectorID: "c", Capability: "read", Action: "read", Resource: "repo/x"}}
}
func TestPreflightAndConsumeOnce(t *testing.T) {
	s := NewAuthorizationStore()
	in := PreflightInput{Binding: testBinding(), ValidatedArgs: []byte(`{"id":"x"}`), Planner: plannerFunc(func([]byte, BindingContext) ([]Operation, error) { return testPlan(), nil }), Authorizer: authorizerFunc(func(i, s, a, tool string, o Operation) (string, bool, error) { return "sha256:bundle", true, nil })}
	grant, err := s.Preflight(in, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Consume(grant.Handle, in.Binding, testPlan()[0]); err != nil {
		t.Fatal(err)
	}
	if err = s.Consume(grant.Handle, in.Binding, testPlan()[0]); !errors.Is(err, ErrAuthorizationInvalid) {
		t.Fatalf("replay = %v", err)
	}
}
func TestPreflightRequiresCompletePlanAndANDAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name  string
		plan  []Operation
		allow bool
	}{{"missing", nil, true}, {"denied", testPlan(), false}} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewAuthorizationStore()
			_, err := s.Preflight(PreflightInput{Binding: testBinding(), ValidatedArgs: []byte(`{}`), Planner: plannerFunc(func([]byte, BindingContext) ([]Operation, error) { return tc.plan, nil }), Authorizer: authorizerFunc(func(string, string, string, string, Operation) (string, bool, error) {
				return "sha256:bundle", tc.allow, nil
			})}, time.Second)
			if err == nil {
				t.Fatal("expected deny")
			}
		})
	}
}
func TestAuthorizationConsumeIsAtomic(t *testing.T) {
	s := NewAuthorizationStore()
	in := PreflightInput{Binding: testBinding(), ValidatedArgs: []byte(`{}`), Planner: plannerFunc(func([]byte, BindingContext) ([]Operation, error) { return testPlan(), nil }), Authorizer: authorizerFunc(func(string, string, string, string, Operation) (string, bool, error) {
		return "sha256:bundle", true, nil
	})}
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
			if s.Consume(grant.Handle, in.Binding, testPlan()[0]) == nil {
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
func TestConsumeRejectsChangedBindingAndExpiredHandle(t *testing.T) {
	s := NewAuthorizationStore()
	now := time.Now()
	s.now = func() time.Time { return now }
	in := PreflightInput{Binding: testBinding(), ValidatedArgs: []byte(`{}`), Planner: plannerFunc(func([]byte, BindingContext) ([]Operation, error) { return testPlan(), nil }), Authorizer: authorizerFunc(func(string, string, string, string, Operation) (string, bool, error) {
		return "sha256:bundle", true, nil
	})}
	grant, err := s.Preflight(in, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	changed := in.Binding
	changed.Subject = "other"
	if err = s.Consume(grant.Handle, changed, testPlan()[0]); !errors.Is(err, ErrAuthorizationInvalid) {
		t.Fatalf("changed target = %v", err)
	}
	now = now.Add(time.Second)
	if err = s.Consume(grant.Handle, in.Binding, testPlan()[0]); !errors.Is(err, ErrAuthorizationInvalid) {
		t.Fatalf("expired = %v", err)
	}
}
