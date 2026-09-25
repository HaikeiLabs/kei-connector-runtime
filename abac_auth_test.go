package connectorruntime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestABACClientSendsAPIKeyHeader: the proxy authenticates itself to the ABAC
// engine on the authorize hot path via X-KEI-API-Key (ADR-009), leaving
// Authorization free for the platform transport layer.
func TestABACClientSendsAPIKeyHeader(t *testing.T) {
	var gotKey, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-KEI-API-Key")
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":"allow"}`))
	}))
	defer srv.Close()

	client := NewABACClient(srv.URL, "proxy-abac-secret", 5*time.Second)
	if _, err := client.Authorize(context.Background(), AuthorizeRequest{Action: "github:read"}); err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	if gotKey != "proxy-abac-secret" {
		t.Fatalf("X-KEI-API-Key = %q, want %q", gotKey, "proxy-abac-secret")
	}
	if gotAuth != "" {
		t.Fatalf("Authorization must stay free for the transport layer, got %q", gotAuth)
	}
}

// TestABACClientNoSecretSkipsAuthHeader: local development sends no header,
// matching an engine running without API_SECRET.
func TestABACClientNoSecretSkipsAuthHeader(t *testing.T) {
	var hadKey bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, hadKey = r.Header["X-KEI-API-Key"]
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":"allow"}`))
	}))
	defer srv.Close()

	client := NewABACClient(srv.URL, "", 5*time.Second)
	if _, err := client.Authorize(context.Background(), AuthorizeRequest{Action: "github:read"}); err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	if hadKey {
		t.Fatal("expected no X-KEI-API-Key header when no secret is configured")
	}
}

// TestABACClientFailsClosedOnRejectedCredentials: a 401/403 from the engine
// must surface as an error, never as a decision the caller could act on.
func TestABACClientFailsClosedOnRejectedCredentials(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// A body that would parse as an allow if it were ever trusted.
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"decision":"allow"}`))
			}))
			defer srv.Close()

			client := NewABACClient(srv.URL, "wrong-secret", 5*time.Second)
			resp, err := client.Authorize(context.Background(), AuthorizeRequest{Action: "github:read"})
			if err == nil {
				t.Fatalf("expected error on %d, got decision %+v", status, resp)
			}
			if resp != nil {
				t.Fatalf("expected nil response on %d, got %+v", status, resp)
			}
			if !strings.Contains(err.Error(), "rejected proxy credentials") {
				t.Errorf("error = %v, want it to name rejected credentials", err)
			}
		})
	}
}

// TestConfigValidateRequiresABACSecretInProduction: the proxy refuses to run
// unauthenticated in production or staging.
func TestConfigValidateRequiresABACSecretInProduction(t *testing.T) {
	for _, env := range []string{"production", "prod", "staging", "Production"} {
		t.Run(env, func(t *testing.T) {
			cfg := Config{Env: env, ABACSecret: ""}
			if err := cfg.Validate(); err == nil {
				t.Fatalf("ENV=%s with no ABAC_API_SECRET must fail closed", env)
			}

			cfg.ABACSecret = "present"
			if err := cfg.Validate(); err != nil {
				t.Fatalf("ENV=%s with a secret should validate: %v", env, err)
			}
		})
	}
}

// TestConfigValidateAllowsLocalWithoutSecret: local development is unaffected.
func TestConfigValidateAllowsLocalWithoutSecret(t *testing.T) {
	for _, env := range []string{"local", "dev", ""} {
		cfg := Config{Env: env, ABACSecret: ""}
		if err := cfg.Validate(); err != nil {
			t.Errorf("ENV=%q should not require a secret: %v", env, err)
		}
	}
}

func TestRuntimeConfigDoesNotRequireInternalABACSecret(t *testing.T) {
	cfg := Config{
		Env:                    "production",
		RuntimeToken:           "kh_live_runtime_test_token_1234567890",
		RuntimeControlPlaneURL: "https://control-plane.example.test",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("customer runtime should authenticate with its runtime token, not ABAC_API_SECRET: %v", err)
	}
	if got := cfg.RuntimeToken; got != "kh_live_runtime_test_token_1234567890" {
		t.Fatalf("RuntimeToken = %q, want runtime token", got)
	}
}

func TestRuntimeConfigRequiresControlPlaneURL(t *testing.T) {
	cfg := Config{RuntimeToken: "kh_live_runtime_test_token_1234567890"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("runtime token without a control-plane URL must fail")
	}
}

func TestRuntimeConfigRejectsPlainHTTPInProduction(t *testing.T) {
	cfg := Config{
		Env:                    "production",
		RuntimeToken:           "kh_live_runtime_test_token_1234567890",
		RuntimeControlPlaneURL: "http://control-plane.example.test",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("production runtime must reject a plaintext control-plane URL")
	}
}

func TestRuntimeConfigAllowsPlainHTTPLocally(t *testing.T) {
	cfg := Config{
		Env:                    "local",
		RuntimeToken:           "kh_live_runtime_test_token_1234567890",
		RuntimeControlPlaneURL: "http://control-plane.local",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("local runtime should allow HTTP for development: %v", err)
	}
}

// TestConfigFromEnvReadsABACSecret confirms the wiring from the environment.
func TestConfigFromEnvReadsABACSecret(t *testing.T) {
	t.Setenv("ABAC_API_SECRET", "from-env")
	t.Setenv("ENV", "production")

	cfg := configFromEnv()
	if cfg.ABACSecret != "from-env" {
		t.Errorf("ABACSecret = %q, want from-env", cfg.ABACSecret)
	}
	if !cfg.IsProduction() {
		t.Error("expected IsProduction() for ENV=production")
	}
}
