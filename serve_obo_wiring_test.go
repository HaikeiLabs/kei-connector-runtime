package connectorruntime

import (
	"context"
	"errors"
	"testing"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/credentials/obo"
)

// HAI-669 (R1): serve builds the on-behalf-of exchanger in its real startup
// path (newServeLocalPDP) and hands it to the local PDP, reading descriptors
// from the bundle in force. Removing the wiring fails this test.
func TestServeWiresTheOnBehalfOfExchanger(t *testing.T) {
	cfg := identityServeConfig(t, "https://control-plane.example.test")
	local, _, err := newServeLocalPDP(cfg, serveSeams{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(local.Close)
	ex := local.OnBehalfOfExchanger()
	if ex == nil {
		t.Fatal("identity-mode serve has no on-behalf-of exchanger")
	}
	if _, ok := ex.(*obo.Exchanger); !ok {
		t.Fatalf("exchanger is %T, want *obo.Exchanger", ex)
	}
	// With no bundle in force there is no descriptor: fail closed, no exchange.
	token, _, err := ex.Exchange(context.Background(), "user-1", "c-obo", "a.b.c")
	var e *obo.Error
	if token != "" || !errors.As(err, &e) || e.Code != "descriptor_invalid" {
		t.Fatalf("Exchange without a bundle = %q, %v; want descriptor_invalid", token, err)
	}
}

// Legacy credential release runs no connector calls in the daemon, so it has
// no exchanger.
func TestServeLegacyHasNoOnBehalfOfExchanger(t *testing.T) {
	cfg := identityServeConfig(t, "https://control-plane.example.test")
	cfg.CredentialRelease = CredentialReleaseLegacy
	local, _, err := newServeLocalPDP(cfg, serveSeams{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(local.Close)
	if ex := local.OnBehalfOfExchanger(); ex != nil {
		t.Fatalf("legacy serve has an exchanger: %T", ex)
	}
}
