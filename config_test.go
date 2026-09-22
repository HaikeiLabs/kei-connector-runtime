package main

import (
	"testing"
)

func TestValidateRuntimeTokenFormatAcceptsValidToken(t *testing.T) {
	token := "kh_live_abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	if err := ValidateRuntimeTokenFormat(token); err != nil {
		t.Fatalf("ValidateRuntimeTokenFormat(...) = %v", err)
	}
}

func TestValidateRuntimeTokenFormatRejectsEmpty(t *testing.T) {
	if err := ValidateRuntimeTokenFormat(""); err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestValidateRuntimeTokenFormatRejectsNonStandardPrefix(t *testing.T) {
	if err := ValidateRuntimeTokenFormat("runtime-token-1234567890abcde"); err == nil {
		t.Fatal("expected error for non-standard token prefix")
	}
}

func TestValidateRuntimeTokenFormatRejectsShortToken(t *testing.T) {
	if err := ValidateRuntimeTokenFormat("short"); err == nil {
		t.Fatal("expected error for token that is too short")
	}
}

func TestConfigFromEnvIgnoresLegacyHarnessToken(t *testing.T) {
	t.Setenv("KEI_HARNESS_TOKEN", "kh_live_something")
	// KEI_RUNTIME_TOKEN is deliberately NOT set.
	cfg := configFromEnv()
	if cfg.RuntimeToken != "" {
		t.Fatal("RuntimeToken should be empty when only legacy KEI_HARNESS_TOKEN is set")
	}
	if cfg.IsRuntime() {
		t.Fatal("IsRuntime should be false when KEI_RUNTIME_TOKEN is not set")
	}
}
