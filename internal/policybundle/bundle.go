package policybundle

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/harnessmatch"
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

const ContentType = "application/vnd.kei.policy-bundle.v1+json"
const Issuer = "kei-policy-catalog"

var (
	ErrBundleExpired     = errors.New("policy bundle expired")
	ErrBundleUnsupported = errors.New("policy bundle unsupported")
)

type Audience struct {
	InstallationID string `json:"installation_id"`
	OrgID          string `json:"org_id"`
	WorkspaceID    string `json:"workspace_id"`
}

// Identity is one known user in a bundle with subject_resolution.mode=bundle.
type Identity struct {
	Source       string    `json:"source,omitempty"`
	ExternalID   string    `json:"external_id,omitempty"`
	UserID       string    `json:"user_id"`
	Status       string    `json:"status"`
	Groups       []string  `json:"groups,omitempty"`
	OrgRoles     []string  `json:"org_roles,omitempty"`
	SubjectToken string    `json:"subject_token,omitempty"`
	ExpireTime   time.Time `json:"expire_time,omitempty"`
}

// Harness is one registered coding-agent harness (ADR-029 §2).
type Harness struct {
	AgentID string `json:"agent_id"`
	Kind    string `json:"kind"`
}

type Payload struct {
	Schema         string    `json:"schema"`
	BundleID       string    `json:"bundle_id"`
	BundleVersion  int64     `json:"bundle_version"`
	PolicyRevision int64     `json:"policy_revision"`
	Issuer         string    `json:"issuer"`
	Audience       Audience  `json:"audience"`
	IssuedAt       time.Time `json:"issued_at"`
	NotAfter       time.Time `json:"not_after"`
	Refresh        struct {
		PollIntervalSeconds int `json:"poll_interval_seconds"`
		StaleAfterSeconds   int `json:"stale_after_seconds"`
	} `json:"refresh"`
	SubjectResolution struct {
		Mode            string `json:"mode"`
		MaxCacheSeconds int    `json:"max_cache_seconds"`
	} `json:"subject_resolution"`
	PolicySet              json.RawMessage `json:"policy_set"`
	AgentConnectorBindings json.RawMessage `json:"agent_connector_bindings"`
	Identities             []Identity      `json:"identities,omitempty"`
	Harnesses              []Harness       `json:"harnesses,omitempty"`
	HarnessMatchSemantics  string          `json:"harness_match_semantics,omitempty"`
}

type Verified struct {
	Payload      Payload
	PayloadBytes []byte
	Digest       string
}

// Validate checks an unsigned catalog bundle retrieved over the authenticated
// HTTPS runtime-control-plane connection. The digest binds the exact received
// bytes to the catalog ETag and persisted state; it is not a signature.
func Validate(bundleBytes []byte, installationID, orgID, workspaceID string, highestVersion int64, now time.Time) (*Verified, error) {
	if len(bundleBytes) == 0 {
		return nil, errors.New("empty policy bundle")
	}
	if err := RejectDuplicateJSON(bundleBytes); err != nil {
		return nil, err
	}
	var identity struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(bundleBytes, &identity); err != nil {
		return nil, fmt.Errorf("decode policy bundle identity: %w", err)
	}
	if identity.Schema != "kei.policy-bundle/v1" {
		return nil, ErrBundleUnsupported
	}
	if err := validatePayloadSchema(bundleBytes); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "additional properties") {
			return nil, fmt.Errorf("%w: closed schema rejected unknown field", ErrBundleUnsupported)
		}
		return nil, fmt.Errorf("invalid policy bundle schema: %w", err)
	}
	var payload Payload
	if err := strictJSON(bundleBytes, &payload); err != nil {
		return nil, fmt.Errorf("decode policy bundle: %w", err)
	}
	if payload.Issuer != Issuer || payload.BundleID == "" || payload.BundleVersion < 1 || payload.PolicyRevision < 1 {
		return nil, errors.New("invalid policy bundle identity")
	}
	if payload.Audience.InstallationID != installationID || payload.Audience.OrgID != orgID || payload.Audience.WorkspaceID != workspaceID {
		return nil, errors.New("policy bundle audience mismatch")
	}
	if payload.BundleVersion <= highestVersion {
		return nil, errors.New("policy bundle version rollback or replay")
	}
	if payload.IssuedAt.After(now.Add(5 * time.Minute)) {
		return nil, errors.New("policy bundle issued too far in the future")
	}
	if !now.Before(payload.NotAfter) {
		return nil, ErrBundleExpired
	}
	if payload.NotAfter.After(payload.IssuedAt.Add(24*time.Hour)) || !payload.NotAfter.After(payload.IssuedAt) {
		return nil, errors.New("invalid policy bundle validity window")
	}
	switch payload.SubjectResolution.Mode {
	case "online":
		if payload.SubjectResolution.MaxCacheSeconds > 60 {
			return nil, ErrBundleUnsupported
		}
	case "bundle":
	default:
		return nil, ErrBundleUnsupported
	}
	if err := validatePolicyDialect(payload.PolicySet); err != nil {
		return nil, err
	}
	if err := validateHarnesses(payload.Harnesses, payload.HarnessMatchSemantics); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBundleUnsupported, err)
	}
	digest := sha256.Sum256(bundleBytes)
	return &Verified{Payload: payload, PayloadBytes: append([]byte(nil), bundleBytes...), Digest: fmt.Sprintf("sha256:%x", digest)}, nil
}

var schemaValidator func([]byte) error

func SetSchemaValidator(v func([]byte) error) { schemaValidator = v }

func validatePayloadSchema(raw []byte) error {
	if err := RejectDuplicateJSON(raw); err != nil {
		return err
	}
	if schemaValidator == nil {
		return errors.New("policy bundle schema validator is unavailable")
	}
	return schemaValidator(raw)
}

func validatePolicyDialect(raw json.RawMessage) error {
	var v struct {
		MatchSemantics string `json:"match_semantics"`
		Evaluation     struct {
			Order   string `json:"order"`
			Default string `json:"default"`
		} `json:"evaluation"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	if v.MatchSemantics != "kei.match/v1" || v.Evaluation.Order != "array_order_first_match" || v.Evaluation.Default != "deny" {
		return ErrBundleUnsupported
	}
	return nil
}

func validateHarnesses(harnesses []Harness, semantics string) error {
	if len(harnesses) == 0 && semantics == "" {
		return nil
	}
	if semantics != "kei.harness-match/v1" {
		return fmt.Errorf("harness_match_semantics must be %q", "kei.harness-match/v1")
	}
	for i, h := range harnesses {
		if !harnessmatch.Kinds[h.Kind] {
			return fmt.Errorf("harnesses[%d].kind %q is not a valid harness kind", i, h.Kind)
		}
		if !idPattern.MatchString(h.AgentID) {
			return fmt.Errorf("harnesses[%d].agent_id %q is not a valid identifier", i, h.AgentID)
		}
		if harnessmatch.Kinds[h.AgentID] {
			return fmt.Errorf("harnesses[%d].agent_id %q must not equal a harness kind value", i, h.AgentID)
		}
	}
	return nil
}

func strictJSON(raw []byte, dst any) error {
	if err := RejectDuplicateJSON(raw); err != nil {
		return err
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

// RejectDuplicateJSON prevents ambiguous last-key-wins parsing of bundle bytes.
func RejectDuplicateJSON(raw []byte) error {
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.UseNumber()
	var value func() error
	value = func() error {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				keyTok, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := keyTok.(string)
				if !ok {
					return errors.New("invalid JSON object key")
				}
				if seen[key] {
					return fmt.Errorf("duplicate JSON object key %q", key)
				}
				seen[key] = true
				if err := value(); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("malformed JSON object")
			}
		case '[':
			for d.More() {
				if err := value(); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("malformed JSON array")
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		return nil
	}
	if err := value(); err != nil {
		return err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}
