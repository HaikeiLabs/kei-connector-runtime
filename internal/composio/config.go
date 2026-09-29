package composio

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	connectors "github.com/HaikeiLabs/kei-connector-contracts"
)

// CredentialLabel marks every Composio call in audit as using credentials held
// by a third party (Composio), not by the tenant's secret store. Only the
// Composio project API key is tenant-side; provider OAuth tokens live in
// Composio's connected accounts.
const CredentialLabel = "third-party-managed"

// MaxResponseBytes is the ceiling for a configured response cap. A connector
// may lower it but never raise it.
const MaxResponseBytes int64 = 1 << 20

const defaultTimeoutMS = 10_000

// Tool pins one Composio tool behind one Kei capability. Version must be an
// explicit toolkit version: "latest" would let Composio change the tool's
// schema or behavior under an approved policy.
type Tool struct {
	Slug    string `json:"slug"`
	Version string `json:"version"`
	Action  string `json:"action"`
}

// Config is one Composio connector's local runtime configuration. Tools is the
// allow-list: a capability that is not a key here never reaches Composio, even
// if Kei policy allows it.
type Config struct {
	Enabled          bool              `json:"enabled"`
	CredentialLabel  string            `json:"credential_label"`
	APIKeyRef        string            `json:"api_key_ref"`
	ResponseMaxBytes int64             `json:"response_max_bytes"`
	TimeoutMS        int               `json:"timeout_ms"`
	RedactFields     []string          `json:"redact_fields"`
	Subjects         map[string]string `json:"subjects"`
	Tools            map[string]Tool   `json:"tools"`
}

var (
	capabilityPattern = regexp.MustCompile(`^composio\.([a-z0-9_]+)\.([a-z0-9_]+)$`)
	versionPattern    = regexp.MustCompile(`^[0-9]{8}_[0-9]{2}$`)
	validActions      = map[string]bool{"read": true, "create": true, "update": true, "delete": true, "comment": true}
)

// LoadConfig reads and validates a connector config. Enabled defaults to
// false, so a config that does not opt in is inert.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read composio config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse composio config: %w", err)
	}
	if cfg.TimeoutMS == 0 {
		cfg.TimeoutMS = defaultTimeoutMS
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate is fail-closed: every tool must be pinned, correctly named, and
// classified, and the API key must be an opaque secret-manager reference.
func (c Config) Validate() error {
	if c.CredentialLabel != CredentialLabel {
		return fmt.Errorf("credential_label must be %q", CredentialLabel)
	}
	if connectors.ValidateCredentialRef(c.APIKeyRef) != nil {
		return errors.New("api_key_ref must be an opaque secret reference")
	}
	if c.ResponseMaxBytes <= 0 || c.ResponseMaxBytes > MaxResponseBytes {
		return fmt.Errorf("response_max_bytes must be between 1 and %d", MaxResponseBytes)
	}
	if c.TimeoutMS <= 0 || c.TimeoutMS > 60_000 {
		return errors.New("timeout_ms must be between 1 and 60000")
	}
	for capability, tool := range c.Tools {
		m := capabilityPattern.FindStringSubmatch(capability)
		if m == nil {
			return fmt.Errorf("capability %q must be composio.<toolkit>.<action>", capability)
		}
		want, err := CapabilityName(m[1], tool.Slug)
		if err != nil || want != capability {
			return fmt.Errorf("capability %q does not name tool %q", capability, tool.Slug)
		}
		if !versionPattern.MatchString(tool.Version) {
			return fmt.Errorf("capability %q must pin an explicit toolkit version", capability)
		}
		if !validActions[tool.Action] {
			return fmt.Errorf("capability %q has unknown action %q", capability, tool.Action)
		}
	}
	return nil
}

// CapabilityName maps a Composio tool slug to its Kei capability name,
// composio.<toolkit>.<action>: GITHUB_GET_A_REPOSITORY in toolkit github is
// composio.github.get_a_repository. A slug outside its toolkit is rejected.
func CapabilityName(toolkit, slug string) (string, error) {
	toolkit = strings.ToLower(toolkit)
	prefix := strings.ToUpper(toolkit) + "_"
	if toolkit == "" || !strings.HasPrefix(slug, prefix) || len(slug) == len(prefix) || slug != strings.ToUpper(slug) {
		return "", fmt.Errorf("tool slug %q is not in toolkit %q", slug, toolkit)
	}
	return "composio." + toolkit + "." + strings.ToLower(strings.TrimPrefix(slug, prefix)), nil
}
