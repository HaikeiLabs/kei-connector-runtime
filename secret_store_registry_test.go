package connectorruntime

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeBackend is a SecretStore that records calls and returns canned values.
// It is shared with the redaction tests.
type fakeBackend struct {
	value     string
	getErr    error
	putErr    error
	getCalled bool
	putCalled bool
	lastRef   string
}

func (f *fakeBackend) Get(ctx context.Context, backend, ref string) (*string, error) {
	f.getCalled = true
	f.lastRef = ref
	if f.getErr != nil {
		return nil, f.getErr
	}
	v := f.value
	return &v, nil
}

func (f *fakeBackend) Put(ctx context.Context, backend, ref, value string) error {
	f.putCalled = true
	f.lastRef = ref
	return f.putErr
}

func (f *fakeBackend) Delete(ctx context.Context, backend, ref string) error { return nil }

func (f *fakeBackend) Validate(ctx context.Context, backend, ref string) error {
	_, err := f.Get(ctx, backend, ref)
	return err
}

func TestCompositeStoreValidatesRefBeforeBackendIO(t *testing.T) {
	fake := &fakeBackend{value: "the-secret"}
	reg := NewBackendRegistry()
	reg.Register("aws-secrets-manager", func() (SecretStore, error) { return fake, nil })
	store, err := NewSecretStoreFromRegistry(reg)
	if err != nil {
		t.Fatalf("NewSecretStoreFromRegistry: %v", err)
	}
	if _, err := store.Get(context.Background(), "aws-secrets-manager", "aws-secrets-manager://us-east-1/123/github-token"); err != nil {
		t.Fatalf("Get(valid ref): %v", err)
	}
	if !fake.getCalled {
		t.Fatal("backend Get was not called for a valid reference")
	}

	fake2 := &fakeBackend{}
	reg2 := NewBackendRegistry()
	reg2.Register("aws-secrets-manager", func() (SecretStore, error) { return fake2, nil })
	store2, _ := NewSecretStoreFromRegistry(reg2)
	_, err = store2.Get(context.Background(), "aws-secrets-manager", "ghp_"+strings.Repeat("a", 36))
	if !errors.Is(err, ErrSecretRefMaterial) {
		t.Fatalf("Get(material ref) = %v, want ErrSecretRefMaterial", err)
	}
	if fake2.getCalled {
		t.Fatal("backend Get was called for an inline-material reference")
	}
}

func TestCompositeStoreUnknownBackend(t *testing.T) {
	fake := &fakeBackend{}
	reg := NewBackendRegistry()
	reg.Register("aws-secrets-manager", func() (SecretStore, error) { return fake, nil })
	store, _ := NewSecretStoreFromRegistry(reg)
	// "vault" is a known backend name (passes reference validation) but is not
	// registered, so resolution fails closed without touching a backend.
	_, err := store.Get(context.Background(), "vault", "secret/kei/x")
	if !errors.Is(err, errSecretStore) {
		t.Fatalf("Get(unregistered backend) = %v, want errSecretStore", err)
	}
}

func TestRegistryLazyConstruction(t *testing.T) {
	calls := 0
	reg := NewBackendRegistry()
	reg.Register("aws-secrets-manager", func() (SecretStore, error) {
		calls++
		return &fakeBackend{}, nil
	})
	store, _ := NewSecretStoreFromRegistry(reg)
	if calls != 0 {
		t.Fatalf("backend constructed eagerly: calls=%d", calls)
	}
	if _, err := store.Get(context.Background(), "aws-secrets-manager", "aws-secrets-manager:///x"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if calls != 1 {
		t.Fatalf("backend not constructed on first use: calls=%d", calls)
	}
}

func TestRegistryMemoizesFailureAndRedactsDetail(t *testing.T) {
	calls := 0
	reg := NewBackendRegistry()
	reg.Register("aws-secrets-manager", func() (SecretStore, error) {
		calls++
		return nil, errors.New("boom: /etc/secret-credentials")
	})
	store, _ := NewSecretStoreFromRegistry(reg)
	_, err := store.Get(context.Background(), "aws-secrets-manager", "aws-secrets-manager:///x")
	if !errors.Is(err, errSecretStore) {
		t.Fatalf("Get = %v, want errSecretStore", err)
	}
	if strings.Contains(err.Error(), "boom") || strings.Contains(err.Error(), "/etc/secret-credentials") {
		t.Fatalf("factory error detail leaked: %v", err)
	}
	_, _ = store.Get(context.Background(), "aws-secrets-manager", "aws-secrets-manager:///x")
	if calls != 1 {
		t.Fatalf("failure not memoized: calls=%d", calls)
	}
}

func TestNewSecretStoreDefaultRegistryIsLazy(t *testing.T) {
	// NewSecretStore must not fail (or construct backends) just because an
	// unused backend's cloud credentials are absent in this environment.
	store, err := NewSecretStore()
	if err != nil {
		t.Fatalf("NewSecretStore: %v", err)
	}
	if store == nil {
		t.Fatal("NewSecretStore returned nil")
	}
}

func TestNewSecretStoreFromEmptyRegistry(t *testing.T) {
	if _, err := NewSecretStoreFromRegistry(NewBackendRegistry()); !errors.Is(err, errSecretStore) {
		t.Fatalf("empty registry = %v, want errSecretStore", err)
	}
	if _, err := NewSecretStoreFromRegistry(nil); !errors.Is(err, errSecretStore) {
		t.Fatalf("nil registry = %v, want errSecretStore", err)
	}
}
