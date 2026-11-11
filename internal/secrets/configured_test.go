package secrets

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeConfiguredBackend is a stub backend used to prove the configured store
// delegates to exactly the backend it was built with.
type fakeConfiguredBackend struct {
	value    string
	getCalls int
}

func (f *fakeConfiguredBackend) Get(ctx context.Context, backend, secretRef string) (*string, error) {
	f.getCalls++
	return &f.value, nil
}

func (f *fakeConfiguredBackend) Put(ctx context.Context, backend, secretRef, value string) error {
	return nil
}

func (f *fakeConfiguredBackend) Delete(ctx context.Context, backend, secretRef string) error {
	return nil
}

func (f *fakeConfiguredBackend) Validate(ctx context.Context, backend, secretRef string) error {
	return nil
}

func TestConfiguredStoreUsesConfiguredBackend(t *testing.T) {
	fake := &fakeConfiguredBackend{value: "the-value"}
	reg := NewBackendRegistry()
	reg.Register("aws-secrets-manager", func() (Store, error) { return fake, nil })

	store, err := newConfiguredStoreFromRegistry("aws-secrets-manager", reg)
	if err != nil {
		t.Fatalf("newConfiguredStoreFromRegistry: %v", err)
	}
	got, err := store.Get(context.Background(), "aws-secrets-manager", "aws-secrets-manager://us-east-1/my-secret")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if *got != "the-value" {
		t.Fatalf("Get = %q, want the-value", *got)
	}
	if fake.getCalls != 1 {
		t.Fatalf("backend Get calls = %d, want 1", fake.getCalls)
	}
}

func TestConfiguredStoreRejectsOtherBackend(t *testing.T) {
	fake := &fakeConfiguredBackend{value: "the-value"}
	reg := NewBackendRegistry()
	reg.Register("aws-secrets-manager", func() (Store, error) { return fake, nil })

	store, err := newConfiguredStoreFromRegistry("aws-secrets-manager", reg)
	if err != nil {
		t.Fatalf("newConfiguredStoreFromRegistry: %v", err)
	}
	const ref = "https://vault.azure.net/secrets/other"
	_, err = store.Get(context.Background(), "azure-key-vault", ref)
	if err == nil {
		t.Fatal("Get with a different backend succeeded, want rejection")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Get error = %v, want ErrUnavailable", err)
	}
	if strings.Contains(err.Error(), ref) {
		t.Fatalf("error echoes the reference: %v", err)
	}
	if fake.getCalls != 0 {
		t.Fatalf("unconfigured backend was called %d times, want 0", fake.getCalls)
	}
}

func TestConfiguredStoreRejectsInlineMaterialRefBeforeBackend(t *testing.T) {
	fake := &fakeConfiguredBackend{value: "the-value"}
	reg := NewBackendRegistry()
	reg.Register("aws-secrets-manager", func() (Store, error) { return fake, nil })

	store, err := newConfiguredStoreFromRegistry("aws-secrets-manager", reg)
	if err != nil {
		t.Fatalf("newConfiguredStoreFromRegistry: %v", err)
	}
	// A token fingerprint ValidateRef rejects as inline secret material.
	const ref = "ghp_abcdefghijklmnopqrstuvwxyz012345"
	_, err = store.Get(context.Background(), "aws-secrets-manager", ref)
	if err == nil {
		t.Fatal("Get with an inline-material ref succeeded, want rejection")
	}
	if fake.getCalls != 0 {
		t.Fatalf("backend was called %d times, want 0 (ref must not reach the backend)", fake.getCalls)
	}
}

func TestConfiguredStoreUnsetBuildsNothing(t *testing.T) {
	store, err := NewConfiguredStore("")
	if err != nil {
		t.Fatalf("NewConfiguredStore(\"\"): %v", err)
	}
	if store == nil {
		t.Fatal("NewConfiguredStore(\"\") returned a nil store")
	}
	_, err = store.Get(context.Background(), "aws-secrets-manager", "aws-secrets-manager://us-east-1/my-secret")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Get error = %v, want ErrUnavailable", err)
	}
	if err := store.Validate(context.Background(), "azure-key-vault", "https://vault.azure.net/secrets/x"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Validate error = %v, want ErrUnavailable", err)
	}
}

func TestConfiguredStoreInvalidValueErrors(t *testing.T) {
	_, err := NewConfiguredStore("vault")
	if err == nil {
		t.Fatal("NewConfiguredStore(vault) succeeded, want an error")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v, want ErrUnavailable", err)
	}
}

func TestNewStoreFromEnvUnset(t *testing.T) {
	t.Setenv("KEI_SECRETS_BACKEND", "")
	store, err := NewStoreFromEnv()
	if err != nil {
		t.Fatalf("NewStoreFromEnv: %v", err)
	}
	_, err = store.Get(context.Background(), "gcp-secret-manager", "projects/p/secrets/s")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Get error = %v, want ErrUnavailable", err)
	}
}

func TestNewStoreFromEnvInvalid(t *testing.T) {
	t.Setenv("KEI_SECRETS_BACKEND", "mounted")
	_, err := NewStoreFromEnv()
	if err == nil {
		t.Fatal("NewStoreFromEnv with an unknown backend succeeded, want an error")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v, want ErrUnavailable", err)
	}
}

func TestNewStoreFromEnvValid(t *testing.T) {
	t.Setenv("KEI_SECRETS_BACKEND", "aws-secrets-manager")
	store, err := NewStoreFromEnv()
	if err != nil {
		t.Fatalf("NewStoreFromEnv: %v", err)
	}
	// The store must exist and route to the configured backend; the call
	// itself fails closed (no AWS credentials in the test) but the error
	// must be the backend's, not a construction error.
	_, err = store.Get(context.Background(), "aws-secrets-manager", "aws-secrets-manager://us-east-1/my-secret")
	if err == nil {
		t.Skip("unexpectedly succeeded; no AWS in test env")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Get error = %v, want ErrUnavailable", err)
	}
}
