package invoke

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	runtimecredentials "github.com/HaikeiLabs/kei-connector-runtime/internal/credentials"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

// HAI-1000: an opaque_ref connector whose credential_ref is external (the
// customer's own secret manager) releases its credential from that ref, once
// credential sync has resolved it into the connector reference index.

const (
	externalConnectorID = "00000000-0000-4000-8000-000000001000"
	externalBackend     = "aws-secrets-manager"
	externalRef         = "aws-secrets-manager://us-east-1/customer/crm/api-key"
	externalValue       = "external-sentinel-1000"
)

type externalSecretStore struct {
	values map[string]string
	reads  []string
}

func (s *externalSecretStore) Get(_ context.Context, backend, ref string) (*string, error) {
	s.reads = append(s.reads, backend+"|"+ref)
	v, ok := s.values[backend+"|"+ref]
	if !ok {
		return nil, errors.New("secret not found")
	}
	return &v, nil
}

func externalDescriptor() policybundle.Connector {
	return policybundle.Connector{
		ID: externalConnectorID, Name: "crm", Provider: "http_api", CredentialSource: "opaque_ref", AccountModel: "shared",
		CredentialRef: externalRef, CredentialBackend: externalBackend,
	}
}

func TestSecretResolverReleasesAnExternalRef(t *testing.T) {
	index := runtimecredentials.ConnectorIndexPath(filepath.Join(t.TempDir(), "state"))
	if err := runtimecredentials.WriteConnectorReference(index, runtimecredentials.ConnectorReference{ConnectorID: externalConnectorID, Field: "api_key", SecretBackend: externalBackend, SecretRef: externalRef, External: true}); err != nil {
		t.Fatal(err)
	}
	store := &externalSecretStore{values: map[string]string{externalBackend + "|" + externalRef: externalValue}}
	got, err := SecretResolver{IndexPath: index, Store: store}.Resolve(context.Background(), externalDescriptor())
	if err != nil || got != externalValue {
		t.Fatalf("got=%q err=%v", got, err)
	}
	if len(store.reads) != 1 || store.reads[0] != externalBackend+"|"+externalRef {
		t.Fatalf("reads = %v", store.reads)
	}
}

func TestSecretResolverExternalRefFailsClosed(t *testing.T) {
	for name, tc := range map[string]struct {
		external bool
		backend  string
		code     string
	}{
		"not resolved by sync":    {external: false, code: "credential_unavailable"},
		"resolved, other backend": {external: true, backend: "azure-key-vault", code: "credential_backend_mismatch"},
	} {
		t.Run(name, func(t *testing.T) {
			index := runtimecredentials.ConnectorIndexPath(filepath.Join(t.TempDir(), "state"))
			if tc.external {
				if err := runtimecredentials.WriteConnectorReference(index, runtimecredentials.ConnectorReference{ConnectorID: externalConnectorID, Field: "api_key", SecretBackend: externalBackend, SecretRef: externalRef, External: true}); err != nil {
					t.Fatal(err)
				}
			}
			store := &externalSecretStore{values: map[string]string{externalBackend + "|" + externalRef: externalValue}}
			descriptor := externalDescriptor()
			if tc.backend != "" {
				descriptor.CredentialBackend = tc.backend
			}
			_, err := SecretResolver{IndexPath: index, Store: store}.Resolve(context.Background(), descriptor)
			var secretErr *SecretError
			if !errors.As(err, &secretErr) || secretErr.Code != tc.code {
				t.Fatalf("err = %v, want %s", err, tc.code)
			}
			if len(store.reads) != 0 {
				t.Fatalf("store read on a deny: %v", store.reads)
			}
			if strings.Contains(err.Error(), externalRef) || strings.Contains(err.Error(), externalValue) {
				t.Fatalf("error leaks the ref or value: %v", err)
			}
		})
	}
}

func TestSecretResolverReleasesABareAzureExternalRef(t *testing.T) {
	t.Setenv("KEI_SECRETS_AZURE_VAULT_URL", "https://acme.vault.azure.net")
	const qualified = "https://acme.vault.azure.net/secrets/crm-api-key"
	index := runtimecredentials.ConnectorIndexPath(filepath.Join(t.TempDir(), "state"))
	if err := runtimecredentials.WriteConnectorReference(index, runtimecredentials.ConnectorReference{ConnectorID: externalConnectorID, Field: "api_key", SecretBackend: "azure-key-vault", SecretRef: qualified, External: true}); err != nil {
		t.Fatal(err)
	}
	store := &externalSecretStore{values: map[string]string{"azure-key-vault|" + qualified: externalValue}}
	descriptor := externalDescriptor()
	descriptor.CredentialRef, descriptor.CredentialBackend = "crm-api-key", "azure-key-vault"
	got, err := SecretResolver{IndexPath: index, Store: store}.Resolve(context.Background(), descriptor)
	if err != nil || got != externalValue || len(store.reads) != 1 {
		t.Fatalf("got=%q err=%v reads=%v", got, err, store.reads)
	}
}
