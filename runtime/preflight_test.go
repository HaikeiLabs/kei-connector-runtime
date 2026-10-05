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
	return BindingContext{InstallationID: "i", BundleDigest: "sha256:bundle", Subject: "u", AgentID: "a", Tool: "t", Route: DispatchRoute{ConnectorBinding: &ConnectorBindingRoute{ConnectorID: "c", RequiredCapabilities: []string{"read"}, ResourceTypes: []ResourceType{{Type: "repository"}}}}}
}
func testPlan() []Operation {
	return []Operation{{ConnectorID: "c", Capability: "read", Action: "read", Resource: "repo/x", ResourceType: "repository"}}
}
func TestRouteUnionRequiresExactlyOneValidBranch(t *testing.T) {
	cases := []DispatchRoute{{}, {ConnectorBinding: &ConnectorBindingRoute{ConnectorID: "c", RequiredCapabilities: []string{"read"}, ResourceTypes: []ResourceType{{Type: "repository"}}}, HarnessExecutor: &HarnessExecutorRoute{ExecutorID: "h"}}, {ConnectorBinding: &ConnectorBindingRoute{ConnectorID: "c", RequiredCapabilities: []string{"read"}}}, {HarnessExecutor: &HarnessExecutorRoute{}}}
	for i, route := range cases {
		if route.valid() {
			t.Fatalf("route %d unexpectedly valid", i)
		}
	}
	if !(DispatchRoute{HarnessExecutor: &HarnessExecutorRoute{ExecutorID: "h"}}).valid() {
		t.Fatal("valid harness route rejected")
	}
}

type argsValidatorFunc func([]byte) ([]byte, error)

func (f argsValidatorFunc) ValidateArgs(b []byte) ([]byte, error) { return f(b) }

func TestPlannerRegistrationRequiresTrustedAgentAndExactRoute(t *testing.T) {
	local := NewLocalPDP(nil, nil)
	reg := ToolOperationRegistration{Route: testBinding().Route, Validator: argsValidatorFunc(func(b []byte) ([]byte, error) { return b, nil }), Planner: plannerFunc(func([]byte, BindingContext) ([]Operation, error) { return testPlan(), nil })}
	if err := local.RegisterOperationPlanner("tool", reg); !errors.Is(err, ErrPlanInvalid) {
		t.Fatalf("missing trusted agent registration = %v", err)
	}
	reg.AgentID = "agent-trusted"
	if err := local.RegisterOperationPlanner("tool", reg); err != nil {
		t.Fatalf("valid registration: %v", err)
	}
}
func TestPlanMustMatchRegisteredCapabilityAndResourceTypes(t *testing.T) {
	for _, op := range []Operation{{ConnectorID: "c", Capability: "extra", Action: "read", Resource: "x", ResourceType: "repository"}, {ConnectorID: "c", Capability: "read", Action: "read", Resource: "x", ResourceType: "issue"}} {
		if err := validatePlan(testBinding().Route, []Operation{op}); !errors.Is(err, ErrPlanInvalid) {
			t.Fatalf("validatePlan(%+v) = %v", op, err)
		}
	}
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
