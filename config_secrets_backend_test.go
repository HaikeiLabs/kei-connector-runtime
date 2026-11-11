package connectorruntime

import (
	"testing"
)

func TestConfigValidateRejectsUnknownSecretsBackend(t *testing.T) {
	t.Setenv("KEI_SECRETS_BACKEND", "mounted")
	t.Setenv("KEI_RUNTIME_TOKEN", "")
	cfg := configFromEnv()
	if cfg.SecretsBackend != "mounted" {
		t.Fatalf("SecretsBackend = %q, want mounted", cfg.SecretsBackend)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate succeeded, want an error for an unknown backend")
	}
}

func TestConfigValidateAcceptsConfiguredSecretsBackend(t *testing.T) {
	t.Setenv("KEI_SECRETS_BACKEND", "aws-secrets-manager")
	t.Setenv("KEI_RUNTIME_TOKEN", "")
	cfg := configFromEnv()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestConfigValidateAcceptsUnsetSecretsBackend(t *testing.T) {
	t.Setenv("KEI_SECRETS_BACKEND", "")
	t.Setenv("KEI_RUNTIME_TOKEN", "")
	cfg := configFromEnv()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}
