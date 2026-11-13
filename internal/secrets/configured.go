package secrets

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// Each runtime install uses exactly one secret store, named by
// KEI_SECRETS_BACKEND (aws-secrets-manager, azure-key-vault, or
// gcp-secret-manager). A deployment that needs no secret store (for example a
// local bring-your-own harness that authenticates with SSO identity) leaves
// the variable unset and every store call fails closed.
const secretsBackendEnvVar = "KEI_SECRETS_BACKEND"

// ValidateBackendName reports whether backend is a legal value for
// KEI_SECRETS_BACKEND: empty (no secret store) or one of the configured
// backends. It is the startup check; the error names the offending value.
func ValidateBackendName(backend string) error {
	if strings.TrimSpace(backend) == "" {
		return nil
	}
	if _, err := DefaultBackendRegistry().Only(backend); err != nil {
		return fmt.Errorf("%s: %w", secretsBackendEnvVar, err)
	}
	return nil
}

// ConfiguredBackendName returns the trimmed KEI_SECRETS_BACKEND value: the
// one backend this runtime's store serves, or "" when none is configured.
func ConfiguredBackendName() string {
	return strings.TrimSpace(os.Getenv(secretsBackendEnvVar))
}

// NewStoreFromEnv builds the runtime's single configured secret store from
// KEI_SECRETS_BACKEND. Unset (or blank) builds a store that fails every call
// with ErrUnavailable; an unknown value is a startup error.
func NewStoreFromEnv() (Store, error) {
	return NewConfiguredStore(os.Getenv(secretsBackendEnvVar))
}

// NewConfiguredStore builds a store over exactly one backend. backend must be
// one of the configured backends; "" builds a store that fails every call
// with ErrUnavailable; any other value is a construction error that names the
// offending value (a backend name, never a secret).
func NewConfiguredStore(backend string) (Store, error) {
	backend = strings.TrimSpace(backend)
	if backend == "" {
		return &configuredStore{backend: ""}, nil
	}
	reg, err := DefaultBackendRegistry().Only(backend)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return newConfiguredStoreFromRegistry(backend, reg)
}

// newConfiguredStoreFromRegistry is the registry seam used by NewConfiguredStore
// and by tests (which register a fake under the configured name). The inner
// store is the existing composite over the given registry, so every ref is
// validated by ValidateRef before any backend I/O.
func newConfiguredStoreFromRegistry(backend string, reg *BackendRegistry) (Store, error) {
	inner, err := NewStoreFromRegistry(reg)
	if err != nil {
		return nil, err
	}
	return &configuredStore{backend: backend, inner: inner}, nil
}

// configuredStore is the runtime's single secret store. It holds at most one
// backend; a call whose backend argument differs from the configured one
// fails closed with ErrUnavailable, and the error never contains the
// reference or a secret value.
type configuredStore struct {
	backend string
	inner   Store
}

// failClosed is the single error shape for this store: generic, no ref, no
// value, no backend-specific detail.
func (s *configuredStore) failClosed() error {
	return fmt.Errorf("%w: secret backend unavailable", ErrUnavailable)
}

// checkBackend fails closed unless the call targets the configured backend.
func (s *configuredStore) checkBackend(backend string) error {
	if s.backend == "" || backend != s.backend {
		return s.failClosed()
	}
	return nil
}

func (s *configuredStore) Get(ctx context.Context, backend, secretRef string) (*string, error) {
	if err := s.checkBackend(backend); err != nil {
		return nil, err
	}
	return s.inner.Get(ctx, backend, secretRef)
}

func (s *configuredStore) Put(ctx context.Context, backend, secretRef, value string) error {
	if err := s.checkBackend(backend); err != nil {
		return err
	}
	return s.inner.Put(ctx, backend, secretRef, value)
}

func (s *configuredStore) Delete(ctx context.Context, backend, secretRef string) error {
	if err := s.checkBackend(backend); err != nil {
		return err
	}
	return s.inner.Delete(ctx, backend, secretRef)
}

func (s *configuredStore) Validate(ctx context.Context, backend, secretRef string) error {
	if err := s.checkBackend(backend); err != nil {
		return err
	}
	return s.inner.Validate(ctx, backend, secretRef)
}
