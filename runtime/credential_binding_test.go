package runtime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCredentialBindingClientResolvesWithRuntimeToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.EscapedPath() != "/api/v1/runtime/credential-bindings/user%2F1/services/github" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.EscapedPath())
		}
		if got := r.Header.Get("Authorization"); got != "Bearer runtime-token" {
			t.Fatalf("authorization = %q", got)
		}
		_ = json.NewEncoder(w).Encode(CredentialDescriptor{
			ID: "binding-1", SecretBackend: "azure-key-vault",
			SecretRef: "https://vault.vault.azure.net/secrets/github-token", Status: "active", Version: 1,
		})
	}))
	defer server.Close()

	client := NewCredentialBindingClient(server.URL, time.Second)
	descriptor, err := client.Resolve(context.Background(), "runtime-token", "user/1", "github")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if descriptor.ID != "binding-1" || descriptor.SecretBackend != "azure-key-vault" {
		t.Fatalf("unexpected descriptor: %+v", descriptor)
	}
}

func TestCredentialBindingClientMapsNotFound(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	client := NewCredentialBindingClient(server.URL, time.Second)
	_, err := client.Resolve(context.Background(), "runtime-token", "user", "github")
	if err == nil || err != ErrCredentialBindingNotFound {
		t.Fatalf("Resolve error = %v, want ErrCredentialBindingNotFound", err)
	}
}
