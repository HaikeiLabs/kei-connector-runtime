package connectorruntime

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/statedir"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

// defaultABACURL is the legacy local catalog address used when ABAC_URL is unset.
const defaultABACURL = "http://localhost:8080"

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
	ToolManifestPath              string
	// PolicyBundleV2Ready is the explicit KEI_POLICY_BUNDLE_V2=1 readiness opt-in.
	PolicyBundleV2Ready bool
	// CredentialRelease is KEI_CREDENTIAL_RELEASE: "legacy" (default) or
	// "identity", where the serve daemon holds session credentials from I11.
	CredentialRelease    string
	CredentialReleaseURL string
	// SessionIdleTTL is KEI_SESSION_IDLE_TTL: how long a named daemon session
	// lives without use (Go duration, default 30m).
	SessionIdleTTL time.Duration
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

func configFromEnv() Config {
	return Config{
		ABACURL:                       envOr("ABAC_URL", defaultABACURL),
		RuntimeControlPlaneURL:        os.Getenv("KEI_RUNTIME_CONTROL_PLANE_URL"),
		RuntimeToken:                  os.Getenv("KEI_RUNTIME_TOKEN"),
		RuntimeStateDir:               envOr("KEI_RUNTIME_STATE_DIR", statedir.DefaultPathOS()),
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
		ToolManifestPath:              os.Getenv("KEI_TOOL_MANIFEST"),
		PolicyBundleV2Ready:           os.Getenv("KEI_POLICY_BUNDLE_V2") == "1",
		CredentialRelease:             envOr("KEI_CREDENTIAL_RELEASE", CredentialReleaseLegacy),
		CredentialReleaseURL:          os.Getenv("KEI_CREDENTIAL_RELEASE_URL"),
		SessionIdleTTL:                sessionIdleTTLFromEnv(),
	}
}

func (c Config) PolicyStateDir() string     { return c.RuntimeStateDir }
func (c Config) Token() string              { return c.RuntimeToken }
func (c Config) ControlPlaneURL() string    { return c.RuntimeControlPlaneURL }
func (c Config) PolicyAuditPath() string    { return c.AuditPath }
func (c Config) PolicyAuditMaxBytes() int64 { return c.AuditMaxBytes }
func (c Config) FlushURL() string           { return c.ABACURL }
func (c Config) FlushSecret() string        { return c.ABACSecret }
func (c Config) SyncKeyID() string          { return c.CredentialSyncKeyID }
func (c Config) SyncPrivateKey() string     { return c.CredentialSyncPrivateKey }

// SubjectResolutionURL is where runtime subject lookups are sent: a catalog
// configured through ABAC_URL, otherwise the runtime control plane, which
// serves the same route. The localhost ABAC default is never used for this,
// because production rejects it and every runtime-mode lookup would deny.
func (c Config) SubjectResolutionURL() string {
	if c.ABACURL == "" || c.ABACURL == defaultABACURL {
		return c.RuntimeControlPlaneURL
	}
	return c.ABACURL
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
	return keiruntime.ValidateRuntimeTokenFormat(token)
}

// Validate fails closed when required service-to-service authentication is
// absent in an environment that requires it.
func (c Config) Validate() error {
	if c.IsRuntime() {
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
	if c.IsProduction() && c.ABACSecret == "" {
		return errors.New("ABAC_API_SECRET is required when ENV is production or staging")
	}
	return nil
}
