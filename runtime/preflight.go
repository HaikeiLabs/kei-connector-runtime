package runtime

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

// DispatchRoute is the typed route contract expected from manifest v3. Keep
// this runtime-owned abstraction independent of the manifest registration
// package so route discovery can be integrated without coupling the planner to
// untrusted wire data.
type DispatchRoute interface{ isDispatchRoute() }

type ConnectorDispatch struct {
	ConnectorID          string
	RequiredCapabilities []string
}

func (ConnectorDispatch) isDispatchRoute() {}

type HarnessDispatch struct{}

func (HarnessDispatch) isDispatchRoute() {}

// Operation is one exact provider operation approved by policy.
type Operation = policybundle.Operation

// BindingContext contains trusted registration and delegation metadata. Args
// must already have been validated against the registered tool schema.
type BindingContext struct {
	InstallationID  string
	BundleDigest    string
	Subject         string
	AgentID         string
	Tool            string
	Route           DispatchRoute
	ParentSpan      string
	DelegationDepth int
}

// OperationPlanner must derive the entire operation set from validated args
// and trusted dispatch metadata. It must not use a capability list supplied by
// the caller. Return an error for response-dependent or otherwise incomplete
// plans; callers must split those workflows into separately preflighted calls.
type OperationPlanner interface {
	Plan(validatedArgs []byte, binding BindingContext) ([]Operation, error)
}

// OperationAuthorizer is implemented by the local PDP integration. Each exact
// operation must be allowed; all results are ANDed before an authorization is
// stored.
type OperationAuthorizer interface {
	AuthorizeOperation(installationID, subject, agentID, tool string, op Operation) (bundleDigest string, allowed bool, err error)
}

type PreflightInput struct {
	Binding       BindingContext
	ValidatedArgs []byte
	Planner       OperationPlanner
	Authorizer    OperationAuthorizer
}
type PreflightResult struct {
	Handle    string    `json:"handle"`
	ExpiresAt time.Time `json:"expires_at"`
}

var (
	ErrPreflightDenied      = errors.New("preflight denied")
	ErrPlanInvalid          = errors.New("operation plan invalid")
	ErrAuthorizationInvalid = errors.New("authorization handle invalid")
)

const (
	minAuthorizationTTL = time.Second
	maxAuthorizationTTL = 30 * time.Second
)

// AuthorizationStore holds approved plans only in process memory. Restart
// therefore invalidates all outstanding authorizations. Handles are random
// bearer secrets; only their SHA-256 digests are retained.
type AuthorizationStore struct {
	mu      sync.Mutex
	entries map[string]*authorizationEntry
	now     func() time.Time
}
type authorizationEntry struct {
	binding    BindingContext
	digest     string
	operations []Operation
	consumed   []bool
	expires    time.Time
}

func NewAuthorizationStore() *AuthorizationStore {
	return &AuthorizationStore{entries: make(map[string]*authorizationEntry), now: time.Now}
}

// Preflight plans, authorizes every exact operation and atomically stores the
// plan only after all checks succeed. No plan or handle is suitable for logs.
func (s *AuthorizationStore) Preflight(in PreflightInput, ttl time.Duration) (PreflightResult, error) {
	if in.Planner == nil || in.Authorizer == nil || len(in.ValidatedArgs) == 0 || in.Binding.InstallationID == "" || in.Binding.BundleDigest == "" || in.Binding.Subject == "" || in.Binding.AgentID == "" || in.Binding.Tool == "" || in.Binding.Route == nil || ttl < minAuthorizationTTL || ttl > maxAuthorizationTTL {
		return PreflightResult{}, ErrPreflightDenied
	}
	ops, err := in.Planner.Plan(append([]byte(nil), in.ValidatedArgs...), in.Binding)
	if err != nil || len(ops) == 0 {
		return PreflightResult{}, ErrPlanInvalid
	}
	if err := validatePlan(in.Binding.Route, ops); err != nil {
		return PreflightResult{}, err
	}
	for _, op := range ops {
		digest, allowed, err := in.Authorizer.AuthorizeOperation(in.Binding.InstallationID, in.Binding.Subject, in.Binding.AgentID, in.Binding.Tool, op)
		if err != nil || !allowed || digest != in.Binding.BundleDigest {
			return PreflightResult{}, ErrPreflightDenied
		}
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return PreflightResult{}, ErrPreflightDenied
	}
	handle := hex.EncodeToString(raw)
	key := sha256.Sum256([]byte(handle))
	keyString := hex.EncodeToString(key[:])
	expires := s.now().Add(ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked(s.now())
	s.entries[keyString] = &authorizationEntry{binding: in.Binding, digest: in.Binding.BundleDigest, operations: append([]Operation(nil), ops...), consumed: make([]bool, len(ops)), expires: expires}
	return PreflightResult{Handle: handle, ExpiresAt: expires}, nil
}

// Consume atomically claims one matching plan entry. Duplicate equal
// operations remain separate entries and may each be consumed once.
func (s *AuthorizationStore) Consume(handle string, binding BindingContext, operation Operation) error {
	key := sha256.Sum256([]byte(handle))
	keyString := hex.EncodeToString(key[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[keyString]
	if e == nil || !s.now().Before(e.expires) || !sameBinding(e.binding, binding) || e.digest != binding.BundleDigest {
		return ErrAuthorizationInvalid
	}
	for i, op := range e.operations {
		if !e.consumed[i] && op == operation {
			e.consumed[i] = true
			all := true
			for _, consumed := range e.consumed {
				all = all && consumed
			}
			if all {
				delete(s.entries, keyString)
			}
			return nil
		}
	}
	return ErrAuthorizationInvalid
}

func (s *AuthorizationStore) purgeLocked(now time.Time) {
	for key, e := range s.entries {
		if !now.Before(e.expires) {
			delete(s.entries, key)
		}
	}
}
func sameBinding(a, b BindingContext) bool {
	return a.InstallationID == b.InstallationID && a.BundleDigest == b.BundleDigest && a.Subject == b.Subject && a.AgentID == b.AgentID && a.Tool == b.Tool && a.ParentSpan == b.ParentSpan && a.DelegationDepth == b.DelegationDepth && routeEqual(a.Route, b.Route)
}
func routeEqual(a, b DispatchRoute) bool {
	switch x := a.(type) {
	case ConnectorDispatch:
		y, ok := b.(ConnectorDispatch)
		return ok && x.ConnectorID == y.ConnectorID && equalStrings(x.RequiredCapabilities, y.RequiredCapabilities)
	case HarnessDispatch:
		_, ok := b.(HarnessDispatch)
		return ok
	}
	return false
}
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func validatePlan(route DispatchRoute, ops []Operation) error {
	r, ok := route.(ConnectorDispatch)
	if !ok {
		return ErrPlanInvalid
	}
	if r.ConnectorID == "" || len(r.RequiredCapabilities) == 0 {
		return ErrPlanInvalid
	}
	seenCaps := map[string]bool{}
	for _, c := range r.RequiredCapabilities {
		if c == "" || seenCaps[c] {
			return ErrPlanInvalid
		}
		seenCaps[c] = true
	}
	covered := map[string]bool{}
	for _, op := range ops {
		if op.ConnectorID != r.ConnectorID || op.Capability == "" || op.Action == "" || op.Resource == "" || !seenCaps[op.Capability] {
			return ErrPlanInvalid
		}
		covered[op.Capability] = true
	}
	for c := range seenCaps {
		if !covered[c] {
			return fmt.Errorf("%w: required capability omitted", ErrPlanInvalid)
		}
	}
	return nil
}
