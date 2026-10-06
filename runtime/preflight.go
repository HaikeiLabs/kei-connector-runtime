package runtime

import (
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
	ConnectorID          string
	RequiredCapabilities []string
}

func (ConnectorDispatch) isDispatchRoute() {}

type Operation = policybundle.Operation

type BindingContext struct {
	InstallationID    string
	BundleVersion     int64
	BundleDigest      string
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
	Plan(validatedArgs []byte, binding BindingContext) ([]Operation, error)
}

type PlanAuthorizer interface {
	AuthorizePlan(binding BindingContext, operations []Operation) (bundleDigest string, bundleVersion int64, allowed bool, err error)
}

type PreflightInput struct {
	Binding       BindingContext
	ValidatedArgs []byte
	Planner       OperationPlanner
	Authorizer    PlanAuthorizer
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
	ops, err := in.Planner.Plan(append([]byte(nil), in.ValidatedArgs...), cloneBinding(in.Binding))
	if err != nil || len(ops) == 0 {
		return PreflightResult{}, ErrPlanInvalid
	}
	if err := validatePlan(in.Binding.Route, ops); err != nil {
		return PreflightResult{}, err
	}
	expectedInputDigest := operationInputDigest(in.ValidatedArgs)
	for _, op := range ops {
		if op.InputDigest != expectedInputDigest {
			return PreflightResult{}, ErrPlanInvalid
		}
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

func sameOperationSet(a, b []Operation) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[Operation]int, len(a))
	for _, operation := range a {
		counts[operation]++
	}
	for _, operation := range b {
		if counts[operation] == 0 {
			return false
		}
		counts[operation]--
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

// Invalidate drops all outstanding plan handles on session change or bundle
// refresh. Process restart also invalidates them because the store is memory-only.
func (s *AuthorizationStore) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.entries)
}

func validBinding(b BindingContext) bool {
	if b.InstallationID == "" || b.BundleVersion < 1 || b.BundleDigest == "" || b.Subject == "" || b.AgentID == "" || b.Tool == "" {
		return false
	}
	route, ok := b.Route.(ConnectorDispatch)
	return ok && route.ConnectorID != "" && len(route.RequiredCapabilities) > 0
}
func (s *AuthorizationStore) purgeLocked(now time.Time) {
	for k, e := range s.entries {
		if !now.Before(e.expires) {
			delete(s.entries, k)
		}
	}
}
func sameBinding(a, b BindingContext) bool {
	return a.InstallationID == b.InstallationID && a.BundleVersion == b.BundleVersion && a.BundleDigest == b.BundleDigest && a.Subject == b.Subject && a.SubjectSource == b.SubjectSource && a.SubjectExternalID == b.SubjectExternalID && a.AgentID == b.AgentID && a.Tool == b.Tool && a.ParentSpan == b.ParentSpan && a.DelegationDepth == b.DelegationDepth && routeEqual(a.Route, b.Route)
}
func routeEqual(a, b DispatchRoute) bool {
	x, ok := a.(ConnectorDispatch)
	if !ok {
		return false
	}
	y, ok := b.(ConnectorDispatch)
	return ok && x.ConnectorID == y.ConnectorID && equalStrings(x.RequiredCapabilities, y.RequiredCapabilities)
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
func cloneOperations(ops []Operation) []Operation { return append([]Operation(nil), ops...) }
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
	if !ok || r.ConnectorID == "" || len(r.RequiredCapabilities) == 0 {
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
	for _, op := range ops {
		if op.ConnectorID != r.ConnectorID || op.Capability == "" || op.Action == "" || !validInputDigest(op.InputDigest) || !caps[op.Capability] {
			return ErrPlanInvalid
		}
		if op.ResourceType == "" && (op.ResourceID != "" || op.ResourceParent != "" || op.ResourceParentType != "" || op.Resource != "") {
			return ErrPlanInvalid
		}
		if op.ResourceType != "" && (op.ResourceID == "" || op.Resource == "") {
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
