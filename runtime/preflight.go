package runtime

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

type DispatchRoute interface{ isDispatchRoute() }

type ConnectorDispatch struct {
	Provider             string
	ConnectorID          string
	RequiredCapabilities []string
}

func (ConnectorDispatch) isDispatchRoute() {}

type Operation = policybundle.Operation

type BindingContext struct {
	SessionID         string
	InstallationID    string
	BundleVersion     int64
	BundleDigest      string
	ArgsDigest        string
	ContextDigest     string
	Subject           string
	SubjectSource     string
	SubjectExternalID string
	AgentID           string
	Tool              string
	Route             DispatchRoute
	ParentSpan        string
	DelegationDepth   int
}

type OperationPlanner interface {
	Plan(validatedArgs, validatedContext []byte, binding BindingContext) ([]Operation, error)
}

type PlanAuthorizer interface {
	AuthorizePlan(binding BindingContext, operations []Operation) (bundleDigest string, bundleVersion int64, allowed bool, err error)
}

type PreflightInput struct {
	Binding          BindingContext
	ValidatedArgs    []byte
	ValidatedContext []byte
	Planner          OperationPlanner
	Authorizer       PlanAuthorizer
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

type AuthorizationStore struct {
	mu      sync.Mutex
	entries map[string]*authorizationEntry
	now     func() time.Time
}
type authorizationEntry struct {
	binding    BindingContext
	operations []Operation
	consumed   []bool
	expires    time.Time
}

func NewAuthorizationStore() *AuthorizationStore {
	return &AuthorizationStore{entries: make(map[string]*authorizationEntry), now: time.Now}
}

// Preflight plans and locally AND-authorizes the whole operation set before
// storing an opaque one-use context. Plans and handles must never be logged.
func (s *AuthorizationStore) Preflight(in PreflightInput, ttl time.Duration) (PreflightResult, error) {
	if in.Planner == nil || in.Authorizer == nil || len(in.ValidatedArgs) == 0 || !validBinding(in.Binding) || ttl < minAuthorizationTTL || ttl > maxAuthorizationTTL {
		return PreflightResult{}, ErrPreflightDenied
	}
	if operationInputDigest(in.ValidatedArgs) != in.Binding.ArgsDigest || operationInputDigest(in.ValidatedContext) != in.Binding.ContextDigest {
		return PreflightResult{}, ErrPlanInvalid
	}
	ops, err := in.Planner.Plan(append([]byte(nil), in.ValidatedArgs...), append([]byte(nil), in.ValidatedContext...), cloneBinding(in.Binding))
	if err != nil || len(ops) == 0 {
		return PreflightResult{}, ErrPlanInvalid
	}
	if err := validatePlan(in.Binding.Route, ops); err != nil {
		return PreflightResult{}, err
	}
	digest, version, allowed, err := in.Authorizer.AuthorizePlan(cloneBinding(in.Binding), cloneOperations(ops))
	if err != nil || !allowed || digest != in.Binding.BundleDigest || version != in.Binding.BundleVersion {
		return PreflightResult{}, ErrPreflightDenied
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return PreflightResult{}, ErrPreflightDenied
	}
	handle := hex.EncodeToString(raw)
	key := sha256.Sum256([]byte(handle))
	expires := s.now().UTC().Add(ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked(s.now())
	s.entries[hex.EncodeToString(key[:])] = &authorizationEntry{binding: cloneBinding(in.Binding), operations: cloneOperations(ops), consumed: make([]bool, len(ops)), expires: expires}
	return PreflightResult{Handle: handle, ExpiresAt: expires}, nil
}

// ValidatePlan checks that a newly resolved complete plan is byte-for-byte
// equivalent as an operation multiset to the stored plan, without consuming it.
func (s *AuthorizationStore) ValidatePlan(handle string, binding BindingContext, operations []Operation, authorizer PlanAuthorizer) error {
	if handle == "" || authorizer == nil {
		return ErrAuthorizationInvalid
	}
	key := sha256.Sum256([]byte(handle))
	keyString := hex.EncodeToString(key[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[keyString]
	if e == nil || !s.now().Before(e.expires) || !sameBinding(e.binding, binding) || !sameOperationSet(e.operations, operations) {
		return ErrAuthorizationInvalid
	}
	digest, version, allowed, err := authorizer.AuthorizePlan(cloneBinding(e.binding), cloneOperations(e.operations))
	if err != nil || !allowed || digest != e.binding.BundleDigest || version != e.binding.BundleVersion || !s.now().Before(e.expires) {
		return ErrAuthorizationInvalid
	}
	return nil
}

func sameOperationForConsume(stored, requested Operation) bool {
	if len(requested.ProviderInput) != 0 {
		return sameOperationSet([]Operation{stored}, []Operation{requested})
	}
	stored.ProviderInput = nil
	return stored.ID == requested.ID && stored.ConnectorID == requested.ConnectorID && stored.Capability == requested.Capability && stored.Action == requested.Action && stored.Resource == requested.Resource && stored.InputDigest == requested.InputDigest && stored.ResourceType == requested.ResourceType && stored.ResourceID == requested.ResourceID && stored.ResourceParent == requested.ResourceParent && stored.ResourceParentType == requested.ResourceParentType
}

func sameOperationSet(a, b []Operation) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x.ID != y.ID || x.ConnectorID != y.ConnectorID || x.Capability != y.Capability || x.Action != y.Action || x.Resource != y.Resource || x.InputDigest != y.InputDigest || x.ResourceType != y.ResourceType || x.ResourceID != y.ResourceID || x.ResourceParent != y.ResourceParent || x.ResourceParentType != y.ResourceParentType || !bytes.Equal(x.ProviderInput, y.ProviderInput) {
			return false
		}
	}
	return true
}

// Consume revalidates the full plan against the current verified bundle while
// atomically consuming one exact item. No provider call may precede success.
func (s *AuthorizationStore) Consume(handle string, binding BindingContext, operation Operation, authorizer PlanAuthorizer) error {
	if handle == "" || authorizer == nil {
		return ErrAuthorizationInvalid
	}
	key := sha256.Sum256([]byte(handle))
	keyString := hex.EncodeToString(key[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[keyString]
	if e == nil || !s.now().Before(e.expires) || !sameBinding(e.binding, binding) {
		return ErrAuthorizationInvalid
	}
	digest, version, allowed, err := authorizer.AuthorizePlan(cloneBinding(e.binding), cloneOperations(e.operations))
	if err != nil || !allowed || digest != e.binding.BundleDigest || version != e.binding.BundleVersion || !s.now().Before(e.expires) {
		delete(s.entries, keyString)
		return ErrAuthorizationInvalid
	}
	for i, op := range e.operations {
		if !e.consumed[i] && sameOperationForConsume(op, operation) {
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

// ConsumePlan atomically consumes the whole ordered plan before a multi-op
// daemon request can begin any provider work.
func (s *AuthorizationStore) ConsumePlan(handle string, binding BindingContext, operations []Operation, authorizer PlanAuthorizer) error {
	if handle == "" || authorizer == nil {
		return ErrAuthorizationInvalid
	}
	key := sha256.Sum256([]byte(handle))
	keyString := hex.EncodeToString(key[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[keyString]
	if e == nil || !s.now().Before(e.expires) || !sameBinding(e.binding, binding) || !sameOperationSet(e.operations, operations) {
		return ErrAuthorizationInvalid
	}
	digest, version, allowed, err := authorizer.AuthorizePlan(cloneBinding(e.binding), cloneOperations(e.operations))
	if err != nil || !allowed || digest != e.binding.BundleDigest || version != e.binding.BundleVersion || !s.now().Before(e.expires) {
		delete(s.entries, keyString)
		return ErrAuthorizationInvalid
	}
	delete(s.entries, keyString)
	return nil
}

// Invalidate drops all outstanding plan handles on session change or bundle
// refresh. Process restart also invalidates them because the store is memory-only.
func (s *AuthorizationStore) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.entries)
}

func validBinding(b BindingContext) bool {
	if b.SessionID == "" || b.InstallationID == "" || b.BundleVersion < 1 || b.BundleDigest == "" || !validInputDigest(b.ArgsDigest) || !validInputDigest(b.ContextDigest) || b.Subject == "" || b.AgentID == "" || b.Tool == "" {
		return false
	}
	route, ok := b.Route.(ConnectorDispatch)
	return ok && route.Provider != "" && route.ConnectorID != "" && len(route.RequiredCapabilities) > 0
}
func (s *AuthorizationStore) purgeLocked(now time.Time) {
	for k, e := range s.entries {
		if !now.Before(e.expires) {
			delete(s.entries, k)
		}
	}
}
func sameBinding(a, b BindingContext) bool {
	return a.SessionID == b.SessionID && a.InstallationID == b.InstallationID && a.BundleVersion == b.BundleVersion && a.BundleDigest == b.BundleDigest && a.ArgsDigest == b.ArgsDigest && a.ContextDigest == b.ContextDigest && a.Subject == b.Subject && a.SubjectSource == b.SubjectSource && a.SubjectExternalID == b.SubjectExternalID && a.AgentID == b.AgentID && a.Tool == b.Tool && a.ParentSpan == b.ParentSpan && a.DelegationDepth == b.DelegationDepth && routeEqual(a.Route, b.Route)
}
func routeEqual(a, b DispatchRoute) bool {
	x, ok := a.(ConnectorDispatch)
	if !ok {
		return false
	}
	y, ok := b.(ConnectorDispatch)
	return ok && x.Provider == y.Provider && x.ConnectorID == y.ConnectorID && equalStrings(x.RequiredCapabilities, y.RequiredCapabilities)
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
func cloneBinding(b BindingContext) BindingContext {
	if route, ok := b.Route.(ConnectorDispatch); ok {
		route.RequiredCapabilities = append([]string(nil), route.RequiredCapabilities...)
		b.Route = route
	}
	return b
}
func cloneOperations(ops []Operation) []Operation {
	cloned := append([]Operation(nil), ops...)
	for i := range cloned {
		cloned[i].ProviderInput = append([]byte(nil), cloned[i].ProviderInput...)
	}
	return cloned
}
func operationInputDigest(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func validInputDigest(digest string) bool {
	if len(digest) != len("sha256:")+64 || digest[:len("sha256:")] != "sha256:" {
		return false
	}
	_, err := hex.DecodeString(digest[len("sha256:"):])
	return err == nil
}
func validatePlan(route DispatchRoute, ops []Operation) error {
	r, ok := route.(ConnectorDispatch)
	if !ok || r.Provider == "" || r.ConnectorID == "" || len(r.RequiredCapabilities) == 0 || len(ops) == 0 || len(ops) > policybundle.MaxPlanOperations {
		return ErrPlanInvalid
	}
	caps := map[string]bool{}
	for _, c := range r.RequiredCapabilities {
		if c == "" || caps[c] {
			return ErrPlanInvalid
		}
		caps[c] = true
	}
	covered := map[string]bool{}
	ids := map[string]bool{}
	for _, op := range ops {
		if op.ID == "" || ids[op.ID] || op.ConnectorID != r.ConnectorID || op.Capability == "" || op.Action == "" || op.Resource == "" || len(op.ProviderInput) == 0 || len(op.ProviderInput) > policybundle.MaxPlanProviderInputBytes || !validInputDigest(op.InputDigest) || op.InputDigest != operationInputDigest(op.ProviderInput) || !caps[op.Capability] {
			return ErrPlanInvalid
		}
		ids[op.ID] = true
		if op.ResourceType == "" && (op.ResourceID != "" || op.ResourceParent != "" || op.ResourceParentType != "") {
			return ErrPlanInvalid
		}
		if op.ResourceType != "" && op.Resource == "" {
			return ErrPlanInvalid
		}
		if op.ResourceParent == "" && op.ResourceParentType != "" || op.ResourceParent != "" && op.ResourceParentType == "" {
			return ErrPlanInvalid
		}
		covered[op.Capability] = true
	}
	for cap := range caps {
		if !covered[cap] {
			return ErrPlanInvalid
		}
	}
	return nil
}
