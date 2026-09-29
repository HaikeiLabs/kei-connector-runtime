package connectorruntime

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	ABACURL                       string
	RuntimeControlPlaneURL        string
	RuntimeToken                  string
	RuntimeStateDir               string
	CredentialSyncKeyID           string
	CredentialSyncPrivateKey      string
	CredentialStoreInstallationID string
	ProviderUserID                string
	RegistryPath                  string
	OIDCBridgeURL                 string
	OIDCBridgeSecret              string
	AuditPath                     string
	AuditMaxBytes                 int64
	ABACSecret                    string
	Env                           string
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envIntOr(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

// auditMaxBytesFromEnv reads the local audit spool cap in bytes from
// KEI_PROXY_AUDIT_MAX_BYTES. Unset, malformed, or non-positive values use the
// 100 MiB default, so a typo can never remove the cap.
func auditMaxBytesFromEnv() int64 {
	if v := strings.TrimSpace(os.Getenv("KEI_PROXY_AUDIT_MAX_BYTES")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return defaultAuditMaxBytes
}

// DefaultRuntimeStateDir is the default directory for persisted policy bundle
// and runtime state. Per ADR-026 §5 the directory must be created with mode
// 0700 and its files with mode 0600.
const DefaultRuntimeStateDir = "/var/lib/kei-proxy"

func configFromEnv() Config {
	return Config{
		ABACURL:                       envOr("ABAC_URL", "http://localhost:8080"),
		RuntimeControlPlaneURL:        os.Getenv("KEI_RUNTIME_CONTROL_PLANE_URL"),
		RuntimeToken:                  os.Getenv("KEI_RUNTIME_TOKEN"),
		RuntimeStateDir:               envOr("KEI_RUNTIME_STATE_DIR", DefaultRuntimeStateDir),
		CredentialSyncKeyID:           os.Getenv("KEI_CREDENTIAL_SYNC_KEY_ID"),
		CredentialSyncPrivateKey:      os.Getenv("KEI_CREDENTIAL_SYNC_PRIVATE_KEY"),
		CredentialStoreInstallationID: os.Getenv("KEI_CREDENTIAL_STORE_INSTALLATION_ID"),
		ProviderUserID:                os.Getenv("KEI_PROXY_PROVIDER_USER"),
		RegistryPath:                  envOr("KEI_PROXY_REGISTRY", "/data/config/tools.yaml"),
		OIDCBridgeURL:                 envOr("OIDC_BRIDGE_URL", "http://oidc-bridge.kei.svc.cluster.local:8081"),
		OIDCBridgeSecret:              envOr("OIDC_BRIDGE_SECRET", ""),
		AuditPath:                     os.Getenv("KEI_PROXY_AUDIT"),
		AuditMaxBytes:                 auditMaxBytesFromEnv(),
		ABACSecret:                    strings.TrimSpace(os.Getenv("ABAC_API_SECRET")),
		Env:                           os.Getenv("ENV"),
	}
}

// IsRuntime identifies the customer-hosted installation path.
func (c Config) IsRuntime() bool {
	return c.RuntimeToken != ""
}

// IsProduction reports whether the proxy runs in an environment where
// unauthenticated calls to the ABAC engine must never be attempted.
func (c Config) IsProduction() bool {
	switch strings.ToLower(c.Env) {
	case "production", "prod", "staging":
		return true
	}
	return false
}

// ValidateRuntimeTokenFormat checks the runtime token is well-formed without
// leaking its value. A malformed token is always a misconfiguration regardless
// of environment.
func ValidateRuntimeTokenFormat(token string) error {
	if token == "" {
		return errors.New("KEI_RUNTIME_TOKEN must not be empty")
	}
	if !strings.HasPrefix(token, "kh_live_") {
		return errors.New("KEI_RUNTIME_TOKEN must start with kh_live_")
	}
	if len(token) < 20 {
		return errors.New("KEI_RUNTIME_TOKEN is too short")
	}
	return nil
}

// Validate fails closed when required service-to-service authentication is
// absent in an environment that requires it.
func (c Config) Validate() error {
	if c.IsRuntime() {
		if err := ValidateRuntimeTokenFormat(c.RuntimeToken); err != nil {
			return err
		}
		if c.RuntimeControlPlaneURL == "" {
			return errors.New("KEI_RUNTIME_CONTROL_PLANE_URL is required when KEI_RUNTIME_TOKEN is set")
		}
		if !strings.HasPrefix(c.RuntimeControlPlaneURL, "https://") && !strings.HasPrefix(c.RuntimeControlPlaneURL, "http://") {
			return fmt.Errorf("KEI_RUNTIME_CONTROL_PLANE_URL must be an absolute http(s) URL")
		}
		if c.IsProduction() && !strings.HasPrefix(c.RuntimeControlPlaneURL, "https://") {
			return errors.New("KEI_RUNTIME_CONTROL_PLANE_URL must use https in production or staging")
		}
		return nil
	}
	if c.IsProduction() && c.ABACSecret == "" {
		return errors.New("ABAC_API_SECRET is required when ENV is production or staging")
	}
	return nil
}
