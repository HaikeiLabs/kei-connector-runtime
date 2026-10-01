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

func TestRuntimeValidateRequiresHTTPSExceptNonProductionLoopback(t *testing.T) {
	base := Config{RuntimeToken: "kh_live_runtime_test_token_1234567890"}
	for _, tc := range []struct {
		name, url, env string
		wantErr        bool
	}{{"external HTTP", "http://control.example", "development", true}, {"loopback HTTP", "http://127.0.0.1:8080", "development", false}, {"production loopback HTTP", "http://127.0.0.1:8080", "production", true}, {"HTTPS", "https://control.example", "production", false}} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			cfg.RuntimeControlPlaneURL = tc.url
			cfg.Env = tc.env
			if err := cfg.Validate(); (err != nil) != tc.wantErr {
				t.Fatalf("Validate() err=%v wantErr=%v", err, tc.wantErr)
			}
		})
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
