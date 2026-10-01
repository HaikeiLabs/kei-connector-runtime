package connectorruntime

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

func TestConfigFromEnvDoesNotEnableRuntimeWithoutCanonicalToken(t *testing.T) {
	cfg := configFromEnv()
	if cfg.RuntimeToken != "" {
		t.Fatal("RuntimeToken should be empty when KEI_RUNTIME_TOKEN is not set")
	}
	if cfg.IsRuntime() {
		t.Fatal("IsRuntime should be false when KEI_RUNTIME_TOKEN is not set")
	}
}

func TestRuntimeValidateAcceptsValidToken(t *testing.T) {
	cfg := Config{
		RuntimeToken:           "kh_live_runtime_test_token_1234567890",
		RuntimeControlPlaneURL: "https://control-plane.example.test",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error: %v", err)
	}
}

func TestConfigFromEnvSetsDefaultRuntimeStateDir(t *testing.T) {
	t.Setenv("KEI_RUNTIME_STATE_DIR", "")
	cfg := configFromEnv()
	if cfg.RuntimeStateDir != DefaultRuntimeStateDir {
		t.Fatalf("RuntimeStateDir = %q, want default %q", cfg.RuntimeStateDir, DefaultRuntimeStateDir)
	}
}

func TestConfigFromEnvReadsRuntimeStateDirFromEnv(t *testing.T) {
	t.Setenv("KEI_RUNTIME_STATE_DIR", "/custom/state")
	cfg := configFromEnv()
	if cfg.RuntimeStateDir != "/custom/state" {
		t.Fatalf("RuntimeStateDir = %q, want /custom/state", cfg.RuntimeStateDir)
	}
}
