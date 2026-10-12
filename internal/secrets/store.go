// Package secrets is the runtime's tenant secret store: the Store interface,
// the pluggable backend registry, the built-in Azure Key Vault, AWS Secrets
// Manager, and GCP Secret Manager backends, and the reference validation every
// backend call passes through first. It knows nothing about how a secret was
// delivered.
package secrets

import (
	"context"
	"fmt"
	"sync"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/secrets/errdef"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/secrets/gcp"
)

// The sentinels are defined in errdef, a leaf both this package and the
// backend subpackages import (a backend cannot import this package back,
// because the registry below imports it).
var (
	// ErrNotFound reports that the reference names no readable secret.
	ErrNotFound = errdef.ErrNotFound
	// ErrUnavailable reports that the backend is unknown, could not be built,
	// or failed the call.
	ErrUnavailable = errdef.ErrUnavailable
	// ErrExists reports a write that conflicts with an existing secret.
	ErrExists = errdef.ErrExists
)

// Store is the interface for external credential backends.
// It supports Azure Key Vault, AWS Secrets Manager, and GCP Secret Manager,
// and any backend registered through the pluggable BackendRegistry.
type Store interface {
	// Get retrieves a secret value from the specified backend.
	// backend is one of the registered backend names, e.g.
	// "azure-key-vault", "aws-secrets-manager", or "gcp-secret-manager"
	// secretRef is a backend-specific reference string
	Get(ctx context.Context, backend, secretRef string) (*string, error)

	// Put stores a secret value in the specified backend.
	// Returns ErrExists if the secret already exists (for versioning)
	Put(ctx context.Context, backend, secretRef, value string) error

	// Delete removes a secret from the specified backend
	Delete(ctx context.Context, backend, secretRef string) error

	// Validate verifies that a secret exists and is readable in the backend
	Validate(ctx context.Context, backend, secretRef string) error
}

// BackendFactory lazily constructs a backend. Lazy construction keeps a
// deployment that uses only one backend from failing because an unrelated
// backend's credentials are absent (e.g. no AWS config on an Azure-only host).
type BackendFactory func() (Store, error)

// BackendRegistry holds pluggable secret backends by name. Backends are
// constructed on first use and memoized, so registration is cheap and a
// misconfigured backend only fails when it is actually selected.
type BackendRegistry struct {
	mu        sync.Mutex
	factories map[string]BackendFactory
	instances map[string]Store
	failures  map[string]error
}

// NewBackendRegistry returns an empty registry.
func NewBackendRegistry() *BackendRegistry {
	return &BackendRegistry{
		factories: map[string]BackendFactory{},
		instances: map[string]Store{},
		failures:  map[string]error{},
	}
}

// Register adds (or replaces) a backend factory.
func (r *BackendRegistry) Register(name string, factory BackendFactory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.factories[name] = factory
	delete(r.instances, name)
	delete(r.failures, name)
}

// Empty reports whether no backend is registered.
func (r *BackendRegistry) Empty() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.factories) == 0
}

// store resolves a backend by name, constructing it lazily on first use. The
// returned error is deliberately limited to the backend name: a factory's
// initialization error can reference credential configuration and must not be
// propagated into logs.
func (r *BackendRegistry) store(name string) (Store, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	factory, ok := r.factories[name]
	if !ok {
		return nil, fmt.Errorf("%w: unknown backend %q", ErrUnavailable, name)
	}
	if instance, ok := r.instances[name]; ok {
		return instance, nil
	}
	if err, ok := r.failures[name]; ok {
		return nil, err
	}
	instance, err := factory()
	if err != nil {
		r.failures[name] = fmt.Errorf("%w: %s", ErrUnavailable, name)
		return nil, r.failures[name]
	}
	r.instances[name] = instance
	return instance, nil
}

// DefaultBackendRegistry returns the built-in backends. All authenticate with
// workload / managed identity; none reads static cloud credentials.
func DefaultBackendRegistry() *BackendRegistry {
	reg := NewBackendRegistry()
	reg.Register("azure-key-vault", func() (Store, error) { return NewAzureKeyVaultStore() })
	reg.Register("aws-secrets-manager", func() (Store, error) { return NewAWSSecretsManagerStore() })
	reg.Register("gcp-secret-manager", func() (Store, error) { return gcp.NewStore(), nil })
	return reg
}

// NewStore returns the default composite store (Azure Key Vault, AWS Secrets
// Manager, and GCP Secret Manager). Backends are constructed lazily, so this
// does not fail because an unused backend's credentials are absent.
func NewStore() (Store, error) {
	return NewStoreFromRegistry(DefaultBackendRegistry())
}

// NewStoreFromRegistry builds a composite store over an explicit set of
// pluggable backends. This is the seam for adding a backend (or a fake in
// tests) without editing the built-in list.
func NewStoreFromRegistry(reg *BackendRegistry) (Store, error) {
	if reg == nil || reg.Empty() {
		return nil, fmt.Errorf("%w: no backends registered", ErrUnavailable)
	}
	return &compositeStore{registry: reg}, nil
}

type compositeStore struct {
	registry *BackendRegistry
}

// Get validates the reference before any backend I/O, so an inline-material or
// malformed reference is rejected without a round trip and without the value
// reaching the backend.
func (s *compositeStore) Get(ctx context.Context, backend, secretRef string) (*string, error) {
	if err := ValidateRef(backend, secretRef); err != nil {
		return nil, err
	}
	store, err := s.registry.store(backend)
	if err != nil {
		return nil, err
	}
	return store.Get(ctx, backend, secretRef)
}

func (s *compositeStore) Put(ctx context.Context, backend, secretRef, value string) error {
	if err := ValidateRef(backend, secretRef); err != nil {
		return err
	}
	store, err := s.registry.store(backend)
	if err != nil {
		return err
	}
	return store.Put(ctx, backend, secretRef, value)
}

func (s *compositeStore) Delete(ctx context.Context, backend, secretRef string) error {
	if err := ValidateRef(backend, secretRef); err != nil {
		return err
	}
	store, err := s.registry.store(backend)
	if err != nil {
		return err
	}
	return store.Delete(ctx, backend, secretRef)
}

func (s *compositeStore) Validate(ctx context.Context, backend, secretRef string) error {
	if err := ValidateRef(backend, secretRef); err != nil {
		return err
	}
	store, err := s.registry.store(backend)
	if err != nil {
		return err
	}
	return store.Validate(ctx, backend, secretRef)
}
