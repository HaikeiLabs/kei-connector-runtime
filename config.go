package connectorruntime

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/secrets"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/statedir"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

type Config struct {
	RuntimeControlPlaneURL        string
	RuntimeToken                  string
	RuntimeStateDir               string
	CredentialSyncKeyID           string
	CredentialSyncPrivateKey      string
	CredentialStoreInstallationID string
	ProviderUserID                string
	AuditPath                     string
	AuditMaxBytes                 int64
	Env                           string
	ToolManifestPath              string
	// CredentialRelease is KEI_CREDENTIAL_RELEASE: "legacy" (default) or
	// "identity", where the serve daemon holds session credentials from I11.
	CredentialRelease    string
	CredentialReleaseURL string
	// SessionIdleTTL is KEI_SESSION_IDLE_TTL: how long a named daemon session
	// lives without use (Go duration, default 30m).
	SessionIdleTTL time.Duration
	// TokenlessOwnerSession enables omitted-session calls on the local owner socket.
	TokenlessOwnerSession bool
	// RuntimeHeartbeatInterval is KEI_RUNTIME_HEARTBEAT_INTERVAL: how often
	// `kei-proxy serve` reports liveness (Go duration, default 1m).
	RuntimeHeartbeatInterval time.Duration
	// ExportableServicePrincipals is KEI_EXPORTABLE_SERVICE_PRINCIPALS: the
	// comma-separated service principal names whose subject token
	// POST /v1/session:subjectToken may return. Empty (default) refuses all.
	ExportableServicePrincipals []string
	// SecretsBackend is KEI_SECRETS_BACKEND: the single secret store this
	// install uses (aws-secrets-manager, azure-key-vault, or
	// gcp-secret-manager). Empty (default) means no secret store; every
	// secret call fails closed.
	SecretsBackend string
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

const defaultAuditMaxBytes int64 = 100 << 20

// sessionIdleTTLFromEnv reads KEI_SESSION_IDLE_TTL (a Go duration such as
// "45m"). Unset, malformed or non-positive values use pdp.DefaultIdleTTL.
func sessionIdleTTLFromEnv() time.Duration {
	if v := strings.TrimSpace(os.Getenv("KEI_SESSION_IDLE_TTL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return pdp.DefaultIdleTTL
}

func tokenlessOwnerSessionFromEnv() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("KEI_TOKENLESS_OWNER_SESSION")))
	switch value {
	case "1", "true", "on":
		return true
	case "0", "false", "off":
		return false
	default:
		// Server/container deployments opt out by default; local desktop installs opt in.
		return os.Getenv("ENV") != "production" && os.Getenv("KEI_RUNTIME_DEPLOYMENT") != "server"
	}
}

// exportableServicePrincipalsFromEnv reads KEI_EXPORTABLE_SERVICE_PRINCIPALS
// (comma-separated principal names). Blank entries are dropped; unset or empty
// yields nil, which keeps subject token export off.
func exportableServicePrincipalsFromEnv() []string {
	var names []string
	for _, name := range strings.Split(os.Getenv("KEI_EXPORTABLE_SERVICE_PRINCIPALS"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}
	return names
}

const defaultRuntimeHeartbeatInterval = time.Minute

// runtimeHeartbeatIntervalFromEnv reads KEI_RUNTIME_HEARTBEAT_INTERVAL (a Go
// duration such as "30s"). Unset, malformed, or sub-second values use the
// one-minute default, the same floor `runtime heartbeat --interval` enforces.
func runtimeHeartbeatIntervalFromEnv() time.Duration {
	if v := strings.TrimSpace(os.Getenv("KEI_RUNTIME_HEARTBEAT_INTERVAL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= time.Second {
			return d
		}
	}
	return defaultRuntimeHeartbeatInterval
}

func configFromEnv() Config {
	return Config{
		RuntimeControlPlaneURL:        os.Getenv("KEI_RUNTIME_CONTROL_PLANE_URL"),
		RuntimeToken:                  os.Getenv("KEI_RUNTIME_TOKEN"),
		RuntimeStateDir:               envOr("KEI_RUNTIME_STATE_DIR", statedir.DefaultPathOS()),
		CredentialSyncKeyID:           os.Getenv("KEI_CREDENTIAL_SYNC_KEY_ID"),
		CredentialSyncPrivateKey:      os.Getenv("KEI_CREDENTIAL_SYNC_PRIVATE_KEY"),
		CredentialStoreInstallationID: os.Getenv("KEI_CREDENTIAL_STORE_INSTALLATION_ID"),
		ProviderUserID:                os.Getenv("KEI_PROXY_PROVIDER_USER"),
		AuditPath:                     os.Getenv("KEI_PROXY_AUDIT"),
		AuditMaxBytes:                 auditMaxBytesFromEnv(),
		Env:                           os.Getenv("ENV"),
		ToolManifestPath:              os.Getenv("KEI_TOOL_MANIFEST"),
		CredentialRelease:             envOr("KEI_CREDENTIAL_RELEASE", CredentialReleaseLegacy),
		CredentialReleaseURL:          os.Getenv("KEI_CREDENTIAL_RELEASE_URL"),
		SessionIdleTTL:                sessionIdleTTLFromEnv(),
		TokenlessOwnerSession:         tokenlessOwnerSessionFromEnv(),
		RuntimeHeartbeatInterval:      runtimeHeartbeatIntervalFromEnv(),
		ExportableServicePrincipals:   exportableServicePrincipalsFromEnv(),
		SecretsBackend:                os.Getenv("KEI_SECRETS_BACKEND"),
	}
}

func (c Config) PolicyStateDir() string     { return c.RuntimeStateDir }
func (c Config) Token() string              { return c.RuntimeToken }
func (c Config) ControlPlaneURL() string    { return c.RuntimeControlPlaneURL }
func (c Config) PolicyAuditPath() string    { return c.AuditPath }
func (c Config) PolicyAuditMaxBytes() int64 { return c.AuditMaxBytes }
func (c Config) SyncKeyID() string          { return c.CredentialSyncKeyID }
func (c Config) SyncPrivateKey() string     { return c.CredentialSyncPrivateKey }

// IsRuntime identifies the customer-hosted installation path.
func (c Config) IsRuntime() bool {
	return c.RuntimeToken != ""
}

// IsProduction reports whether the proxy runs in an environment where the
// control-plane URL must be HTTPS and non-loopback.
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
	return keiruntime.ValidateRuntimeTokenFormat(token)
}

// Validate fails closed when runtime-token configuration is malformed. The
// legacy in-cluster relay mode is gone, so commands that need a runtime token
// report it when no token is configured.
func (c Config) Validate() error {
	if err := secrets.ValidateBackendName(c.SecretsBackend); err != nil {
		return err
	}
	if !c.IsRuntime() {
		return nil
	}
	if _, present := os.LookupEnv("KEI_HARNESS_TOKEN"); present {
		return errors.New("KEI_HARNESS_TOKEN is unsupported; use KEI_RUNTIME_TOKEN")
	}
	if err := ValidateRuntimeTokenFormat(c.RuntimeToken); err != nil {
		return err
	}
	if c.RuntimeControlPlaneURL == "" {
		return errors.New("KEI_RUNTIME_CONTROL_PLANE_URL is required when KEI_RUNTIME_TOKEN is set")
	}
	if err := keiruntime.ValidatePolicyControlPlaneURL(c.RuntimeControlPlaneURL, !c.IsProduction()); err != nil {
		return fmt.Errorf("KEI_RUNTIME_CONTROL_PLANE_URL is invalid: %w", err)
	}
	return nil
}
