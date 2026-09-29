package secrets

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

// azureKeyVaultStore implements Store for Azure Key Vault
type azureKeyVaultStore struct {
	credential azcore.TokenCredential
	clients    map[string]*azsecrets.Client
	mu         sync.Mutex
}

func NewAzureKeyVaultStore() (Store, error) {
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
		return nil, fmt.Errorf("%w: backend is %q, expected azure-key-vault", ErrUnavailable, backend)
	}
	vaultURL, name, version, err := parseKeyVaultSecretRef(secretRef)
	if err != nil {
		return nil, err
	}
	client, err := s.clientFor(vaultURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	secret, err := client.GetSecret(ctx, name, version, nil)
	if err != nil {
		var responseError *azcore.ResponseError
		if errors.As(err, &responseError) && responseError.StatusCode == http.StatusNotFound {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if secret.Value == nil {
		return nil, ErrNotFound
	}
	return secret.Value, nil
}

func (s *azureKeyVaultStore) Put(ctx context.Context, backend, secretRef, value string) error {
	if backend != "azure-key-vault" {
		return fmt.Errorf("%w: backend is %q, expected azure-key-vault", ErrUnavailable, backend)
	}
	vaultURL, name, _, err := parseKeyVaultSecretRef(secretRef)
	if err != nil {
		return err
	}
	client, err := s.clientFor(vaultURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	// SetSecret will create or update (if version is specified, it will only update that version)
	params := azsecrets.SetSecretParameters{
		Value: &value,
	}
	_, err = client.SetSecret(ctx, name, params, nil)
	if err != nil {
		var responseError *azcore.ResponseError
		if errors.As(err, &responseError) && responseError.StatusCode == http.StatusConflict {
			return ErrExists
		}
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return nil
}

func (s *azureKeyVaultStore) Delete(ctx context.Context, backend, secretRef string) error {
	if backend != "azure-key-vault" {
		return fmt.Errorf("%w: backend is %q, expected azure-key-vault", ErrUnavailable, backend)
	}
	vaultURL, name, _, err := parseKeyVaultSecretRef(secretRef)
	if err != nil {
		return err
	}
	client, err := s.clientFor(vaultURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	_, err = client.DeleteSecret(ctx, name, nil)
	if err != nil {
		var responseError *azcore.ResponseError
		if errors.As(err, &responseError) && responseError.StatusCode == http.StatusNotFound {
			// Already deleted, which is fine for idempotency
			return nil
		}
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return nil
}

func (s *azureKeyVaultStore) Validate(ctx context.Context, backend, secretRef string) error {
	// Validate by attempting to get the secret - if it exists and is readable, it's valid
	_, err := s.Get(ctx, backend, secretRef)
	if errors.Is(err, ErrNotFound) {
		return ErrNotFound
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
