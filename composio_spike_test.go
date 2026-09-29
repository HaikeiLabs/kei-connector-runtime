package connectorruntime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/composio"
)

type allowAll struct{}

func (allowAll) Authorize(context.Context, composio.AuthorizeRequest) (composio.Decision, error) {
	return composio.Decision{Decision: "allow"}, nil
}

// TestComposioSpikeUsesSharedSecretPath proves the Composio spike resolves its
// project API key through the runtime's existing secret-store boundary: an
// opaque reference in, the secret only on the outbound request header.
func TestComposioSpikeUsesSharedSecretPath(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		_, _ = w.Write([]byte(`{"data":{"ok":true},"successful":true,"log_id":"log_fixture"}`))
	}))
	defer srv.Close()

	cfg, err := composio.LoadConfig("internal/composio/testdata/config.json")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	exec := composio.Executor{
		Config:      cfg,
		Credentials: SecretStoreCredentialResolver{Store: &fakeSecretStore{value: "fixture-key-from-store"}, Backend: "vault"},
		Client:      srv.Client(),
		BaseURL:     srv.URL,
	}
	res, err := composio.GovernedInvoke(context.Background(), allowAll{}, exec, composio.Invocation{
		Subject:    "user-member-0001",
		Capability: "composio.github.get_a_repository",
		Action:     "read",
		Resource:   "github/repos/acme/widgets",
		TraceID:    "trace-0001",
		Arguments:  json.RawMessage(`{"owner":"acme","repo":"widgets"}`),
	})
	if err != nil {
		t.Fatalf("GovernedInvoke: %v", err)
	}
	if gotKey != "fixture-key-from-store" || !res.Successful {
		t.Fatalf("key = %q, result = %+v", gotKey, res)
	}
}
