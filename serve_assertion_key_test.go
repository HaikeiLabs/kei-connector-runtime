package connectorruntime

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/crm"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/secrets"
)

// assertionStore is a secrets.Store stub; the daemon env only carries it.
type assertionStore struct{ secrets.Store }

func (assertionStore) Get(context.Context, string, string) (*string, error) { return nil, nil }

// The serve daemon runs crm calls itself (KEI_CREDENTIAL_RELEASE=identity), so
// its connector env must carry the assertion key reference and the tenant
// secret store; otherwise every crm call denies assertion_key_unavailable.
func TestDaemonInvokeEnvCarriesServiceAssertionKey(t *testing.T) {
	t.Setenv("KEI_SERVICE_ASSERTION_KEY_BACKEND", "aws-secrets-manager")
	t.Setenv("KEI_SERVICE_ASSERTION_KEY_REF", "aws-secrets-manager://us-east-1/kei/test/crm/assertion-key")
	t.Setenv("KEI_SERVICE_ASSERTION_KID", "kei-rt-00000000-0000-4000-8000-000000000000-1")
	store := assertionStore{}
	var emitted []json.RawMessage
	env := daemonInvokeEnv(Config{RuntimeToken: "rt"}, serveSeams{}, store, func(r json.RawMessage) { emitted = append(emitted, r) })

	want := crm.KeyConfig{
		Backend: "aws-secrets-manager",
		Ref:     "aws-secrets-manager://us-east-1/kei/test/crm/assertion-key",
		KID:     "kei-rt-00000000-0000-4000-8000-000000000000-1",
	}
	if env.AssertionKey != want {
		t.Fatalf("AssertionKey = %+v, want %+v", env.AssertionKey, want)
	}
	if env.Store != store {
		t.Fatalf("Store not carried into the daemon env")
	}
	if env.RuntimeToken != "rt" {
		t.Fatalf("RuntimeToken = %q", env.RuntimeToken)
	}
	if err := env.Audit([]byte(`{"a":1}`)); err != nil || len(emitted) != 1 {
		t.Fatalf("audit not forwarded: err=%v emitted=%d", err, len(emitted))
	}
}

func TestDaemonInvokeEnvWithoutStoreOrKey(t *testing.T) {
	t.Setenv("KEI_SERVICE_ASSERTION_KEY_BACKEND", "")
	t.Setenv("KEI_SERVICE_ASSERTION_KEY_REF", "")
	t.Setenv("KEI_SERVICE_ASSERTION_KID", "")
	env := daemonInvokeEnv(Config{}, serveSeams{}, nil, func(json.RawMessage) {})
	if env.Store != nil {
		t.Fatalf("Store = %v, want nil so crm denies assertion_key_unavailable", env.Store)
	}
	if env.AssertionKey != (crm.KeyConfig{}) {
		t.Fatalf("AssertionKey = %+v, want empty", env.AssertionKey)
	}
}
