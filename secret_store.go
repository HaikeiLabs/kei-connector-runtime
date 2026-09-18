package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

var (
	errSecretNotFound = errors.New("secret not found")
	errSecretStore    = errors.New("secret store unavailable")
	errSecretExists   = errors.New("secret already exists")
)

// SecretStore is the interface for external credential backends.
// It supports both Azure Key Vault and AWS Secrets Manager, and any backend
// registered through the pluggable BackendRegistry.
type SecretStore interface {
	// Get retrieves a secret value from the specified backend.
	// backend is either "azure-key-vault" or "aws-secrets-manager"
	// secretRef is a backend-specific reference string
	Get(ctx context.Context, backend, secretRef string) (*string, error)

	// Put stores a secret value in the specified backend.
	// Returns errSecretExists if the secret already exists (for versioning)
	Put(ctx context.Context, backend, secretRef, value string) error

	// Delete removes a secret from the specified backend
	Delete(ctx context.Context, backend, secretRef string) error

	// Validate verifies that a secret exists and is readable in the backend
	Validate(ctx context.Context, backend, secretRef string) error
}

// BackendFactory lazily constructs a backend. Lazy construction keeps a
// deployment that uses only one backend from failing because an unrelated
// backend's credentials are absent (e.g. no AWS config on an Azure-only host).
type BackendFactory func() (SecretStore, error)

// BackendRegistry holds pluggable secret backends by name. Backends are
// constructed on first use and memoized, so registration is cheap and a
// misconfigured backend only fails when it is actually selected.
type BackendRegistry struct {
	mu        sync.Mutex
	factories map[string]BackendFactory
	instances map[string]SecretStore
	failures  map[string]error
}

// NewBackendRegistry returns an empty registry.
func NewBackendRegistry() *BackendRegistry {
	return &BackendRegistry{
		factories: map[string]BackendFactory{},
		instances: map[string]SecretStore{},
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
func (r *BackendRegistry) store(name string) (SecretStore, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	factory, ok := r.factories[name]
	if !ok {
		return nil, fmt.Errorf("%w: unknown backend %q", errSecretStore, name)
	}
	if instance, ok := r.instances[name]; ok {
		return instance, nil
	}
	if err, ok := r.failures[name]; ok {
		return nil, err
	}
	instance, err := factory()
	if err != nil {
		r.failures[name] = fmt.Errorf("%w: %s", errSecretStore, name)
		return nil, r.failures[name]
	}
	r.instances[name] = instance
	return instance, nil
}

// DefaultBackendRegistry returns the built-in backends. Both authenticate with
// workload / managed identity; neither reads static cloud credentials.
func DefaultBackendRegistry() *BackendRegistry {
	reg := NewBackendRegistry()
	reg.Register("azure-key-vault", func() (SecretStore, error) { return NewAzureKeyVaultStore() })
	reg.Register("aws-secrets-manager", func() (SecretStore, error) { return NewAWSSecretsManagerStore() })
	return reg
}

// NewSecretStore returns the default composite store (Azure Key Vault and AWS
// Secrets Manager). Backends are constructed lazily, so this does not fail
// because an unused backend's credentials are absent.
func NewSecretStore() (SecretStore, error) {
	return NewSecretStoreFromRegistry(DefaultBackendRegistry())
}

// NewSecretStoreFromRegistry builds a composite store over an explicit set of
// pluggable backends. This is the seam for adding a backend (or a fake in
// tests) without editing the built-in list.
func NewSecretStoreFromRegistry(reg *BackendRegistry) (SecretStore, error) {
	if reg == nil || reg.Empty() {
		return nil, fmt.Errorf("%w: no backends registered", errSecretStore)
	}
	return &compositeSecretStore{registry: reg}, nil
}

type compositeSecretStore struct {
	registry *BackendRegistry
}

// Get validates the reference before any backend I/O, so an inline-material or
// malformed reference is rejected without a round trip and without the value
// reaching the backend.
func (s *compositeSecretStore) Get(ctx context.Context, backend, secretRef string) (*string, error) {
	if err := ValidateSecretRef(backend, secretRef); err != nil {
		return nil, err
	}
	store, err := s.registry.store(backend)
	if err != nil {
		return nil, err
	}
	return store.Get(ctx, backend, secretRef)
}

func (s *compositeSecretStore) Put(ctx context.Context, backend, secretRef, value string) error {
	if err := ValidateSecretRef(backend, secretRef); err != nil {
		return err
	}
	store, err := s.registry.store(backend)
	if err != nil {
		return err
	}
	return store.Put(ctx, backend, secretRef, value)
}

func (s *compositeSecretStore) Delete(ctx context.Context, backend, secretRef string) error {
	if err := ValidateSecretRef(backend, secretRef); err != nil {
		return err
	}
	store, err := s.registry.store(backend)
	if err != nil {
		return err
	}
	return store.Delete(ctx, backend, secretRef)
}

func (s *compositeSecretStore) Validate(ctx context.Context, backend, secretRef string) error {
	if err := ValidateSecretRef(backend, secretRef); err != nil {
		return err
	}
	store, err := s.registry.store(backend)
	if err != nil {
		return err
	}
	return store.Validate(ctx, backend, secretRef)
}

// azureKeyVaultStore implements SecretStore for Azure Key Vault
type azureKeyVaultStore struct {
	credential azcore.TokenCredential
	clients    map[string]*azsecrets.Client
	mu         sync.Mutex
}

func NewAzureKeyVaultStore() (SecretStore, error) {
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("create Azure credential: %w", err)
	}
	return &azureKeyVaultStore{credential: credential, clients: make(map[string]*azsecrets.Client)}, nil
}

func (s *azureKeyVaultStore) clientFor(vaultURL string) (*azsecrets.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if client, ok := s.clients[vaultURL]; ok {
		return client, nil
	}
	client, err := azsecrets.NewClient(vaultURL, s.credential, nil)
	if err != nil {
		return nil, fmt.Errorf("create Azure Key Vault client: %w", err)
	}
	s.clients[vaultURL] = client
	return client, nil
}

func (s *azureKeyVaultStore) Get(ctx context.Context, backend, secretRef string) (*string, error) {
	if backend != "azure-key-vault" {
		return nil, fmt.Errorf("%w: backend is %q, expected azure-key-vault", errSecretStore, backend)
	}
	vaultURL, name, version, err := parseKeyVaultSecretRef(secretRef)
	if err != nil {
		return nil, err
	}
	client, err := s.clientFor(vaultURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errSecretStore, err)
	}
	secret, err := client.GetSecret(ctx, name, version, nil)
	if err != nil {
		var responseError *azcore.ResponseError
		if errors.As(err, &responseError) && responseError.StatusCode == http.StatusNotFound {
			return nil, errSecretNotFound
		}
		return nil, fmt.Errorf("%w: %v", errSecretStore, err)
	}
	if secret.Value == nil {
		return nil, errSecretNotFound
	}
	return secret.Value, nil
}

func (s *azureKeyVaultStore) Put(ctx context.Context, backend, secretRef, value string) error {
	if backend != "azure-key-vault" {
		return fmt.Errorf("%w: backend is %q, expected azure-key-vault", errSecretStore, backend)
	}
	vaultURL, name, _, err := parseKeyVaultSecretRef(secretRef)
	if err != nil {
		return err
	}
	client, err := s.clientFor(vaultURL)
	if err != nil {
		return fmt.Errorf("%w: %v", errSecretStore, err)
	}
	// SetSecret will create or update (if version is specified, it will only update that version)
	params := azsecrets.SetSecretParameters{
		Value: &value,
	}
	_, err = client.SetSecret(ctx, name, params, nil)
	if err != nil {
		var responseError *azcore.ResponseError
		if errors.As(err, &responseError) && responseError.StatusCode == http.StatusConflict {
			return errSecretExists
		}
		return fmt.Errorf("%w: %v", errSecretStore, err)
	}
	return nil
}

func (s *azureKeyVaultStore) Delete(ctx context.Context, backend, secretRef string) error {
	if backend != "azure-key-vault" {
		return fmt.Errorf("%w: backend is %q, expected azure-key-vault", errSecretStore, backend)
	}
	vaultURL, name, _, err := parseKeyVaultSecretRef(secretRef)
	if err != nil {
		return err
	}
	client, err := s.clientFor(vaultURL)
	if err != nil {
		return fmt.Errorf("%w: %v", errSecretStore, err)
	}
	_, err = client.DeleteSecret(ctx, name, nil)
	if err != nil {
		var responseError *azcore.ResponseError
		if errors.As(err, &responseError) && responseError.StatusCode == http.StatusNotFound {
			// Already deleted, which is fine for idempotency
			return nil
		}
		return fmt.Errorf("%w: %v", errSecretStore, err)
	}
	return nil
}

func (s *azureKeyVaultStore) Validate(ctx context.Context, backend, secretRef string) error {
	// Validate by attempting to get the secret - if it exists and is readable, it's valid
	_, err := s.Get(ctx, backend, secretRef)
	if errors.Is(err, errSecretNotFound) {
		return errSecretNotFound
	}
	return err
}

func parseKeyVaultSecretRef(secretRef string) (vaultURL, name, version string, err error) {
	u, err := url.Parse(secretRef)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", "", "", fmt.Errorf("invalid Azure Key Vault secret reference")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 || parts[0] != "secrets" || parts[1] == "" || len(parts) > 3 {
		return "", "", "", fmt.Errorf("Azure Key Vault secret reference must be https://<vault>.vault.azure.net/secrets/<name>[/<version>]")
	}
	return u.Scheme + "://" + u.Host, parts[1], func() string {
		if len(parts) == 3 {
			return parts[2]
		}
		return ""
	}(), nil
}
