package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type plannerFunc func([]byte, []byte, BindingContext) ([]Operation, error)

func (f plannerFunc) Plan(args, context []byte, c BindingContext) ([]Operation, error) {
	return f(args, context, c)
}

type planAuthorizerFunc func(BindingContext, []Operation) (string, int64, bool, error)

func (f planAuthorizerFunc) AuthorizePlan(b BindingContext, ops []Operation) (string, int64, bool, error) {
	return f(b, ops)
}

func testBinding() BindingContext {
	return BindingContext{SessionID: "ks_test", InstallationID: "i", BundleVersion: 2, BundleDigest: "sha256:bundle", ArgsDigest: operationInputDigest([]byte(`{"id":"x"}`)), ContextDigest: operationInputDigest([]byte(`{}`)), Subject: "u", SubjectSource: "discord", SubjectExternalID: "ext", AgentID: "a", Tool: "t", Route: ConnectorDispatch{Provider: "github", ConnectorID: "c", RequiredCapabilities: []string{"read", "meta.read"}}}
}
func testInputDigest() string {
	sum := sha256.Sum256([]byte(`{"id":"x"}`))
	return "sha256:" + hex.EncodeToString(sum[:])
}
func testPlan() []Operation {
	digest := testInputDigest()
	input := []byte(`{"id":"x"}`)
	return []Operation{{ID: "one", ConnectorID: "c", Capability: "read", Action: "read", Resource: "repos/x", InputDigest: digest, ProviderInput: input, ResourceType: "repo", ResourceID: "x"}, {ID: "two", ConnectorID: "c", Capability: "meta.read", Action: "read", Resource: "repos/x", InputDigest: digest, ProviderInput: input, ResourceType: "repo", ResourceID: "x"}}
}
func testPreflightInput(allow bool) PreflightInput {
	return PreflightInput{Binding: testBinding(), ValidatedArgs: []byte(`{"id":"x"}`), ValidatedContext: []byte(`{}`), Planner: plannerFunc(func([]byte, []byte, BindingContext) ([]Operation, error) { return testPlan(), nil }), Authorizer: planAuthorizerFunc(func(b BindingContext, ops []Operation) (string, int64, bool, error) {
		return b.BundleDigest, b.BundleVersion, allow, nil
	})}
}

func TestSessionSubstitutionCannotConsumePreflight(t *testing.T) {
	store := NewAuthorizationStore()
	in := testPreflightInput(true)
	grant, err := store.Preflight(in, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	other := cloneBinding(in.Binding)
	other.SessionID = "ks_other"
	if err := store.ConsumePlan(grant.Handle, other, testPlan(), in.Authorizer); !errors.Is(err, ErrAuthorizationInvalid) {
		t.Fatalf("cross-session consume err=%v", err)
	}
	if err := store.ConsumePlan(grant.Handle, in.Binding, testPlan(), in.Authorizer); err != nil {
		t.Fatalf("original session could not consume after substitution denial: %v", err)
	}
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
			in.Planner = plannerFunc(func([]byte, []byte, BindingContext) ([]Operation, error) { return plan, nil })
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
	changedInput := testPlan()[0]
	changedInput.InputDigest = "sha256:" + strings.Repeat("0", 64)
	if err = s.Consume(grant.Handle, in.Binding, changedInput, in.Authorizer); !errors.Is(err, ErrAuthorizationInvalid) {
		t.Fatalf("same target with changed input digest=%v", err)
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
