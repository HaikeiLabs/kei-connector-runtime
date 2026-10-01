package policybundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

const (
	PayloadType = "application/vnd.kei.policy-bundle.v1+json"
	Issuer      = "kei-policy-catalog"
)

var ErrBundleExpired = errors.New("policy bundle expired")

type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}
type KeySet struct {
	Keys          []Key    `json:"keys"`
	RevokedKeyIDs []string `json:"revoked_key_ids"`
}
type Key struct {
	KTY    string `json:"kty"`
	CRV    string `json:"crv"`
	X      string `json:"x"`
	KID    string `json:"kid"`
	Use    string `json:"use"`
	Alg    string `json:"alg"`
	Status string `json:"status"`
}
type Audience struct {
	InstallationID string `json:"installation_id"`
	OrgID          string `json:"org_id"`
	WorkspaceID    string `json:"workspace_id"`
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
}

type Verified struct {
	Payload      Payload
	PayloadBytes []byte
	Digest       string
	KeyIDs       []string
}

// Verify authenticates DSSE PAE bytes against the runtime's authenticated pinned key set
// before parsing and strict-schema validating the payload. Public test keys are never
// accepted by production mode.
func Verify(envBytes []byte, keys KeySet, installationID, orgID, workspaceID string, highestVersion int64, now time.Time, production bool) (*Verified, error) {
	if err := ValidateKeySet(keys); err != nil {
		return nil, fmt.Errorf("invalid pinned signing keys: %w", err)
	}
	var env Envelope
	if err := strictJSON(envBytes, &env); err != nil {
		return nil, fmt.Errorf("decode envelope: %w", err)
	}
	if env.PayloadType != PayloadType || len(env.Signatures) == 0 || len(env.Signatures) > 2 {
		return nil, errors.New("unsupported or malformed policy envelope")
	}
	payloadBytes, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil || len(payloadBytes) == 0 {
		return nil, errors.New("invalid envelope payload encoding")
	}
	pae := dssePAE(env.PayloadType, payloadBytes)
	revoked := make(map[string]bool, len(keys.RevokedKeyIDs))
	for _, id := range keys.RevokedKeyIDs {
		revoked[id] = true
	}
	byID := make(map[string]Key, len(keys.Keys))
	for _, k := range keys.Keys {
		byID[k.KID] = k
	}
	verified := false
	validIDs := make([]string, 0, len(env.Signatures))
	for _, sig := range env.Signatures {
		k, ok := byID[sig.KeyID]
		if !ok || revoked[sig.KeyID] || (k.Status != "active" && k.Status != "retiring") {
			continue
		}
		if production && strings.HasPrefix(sig.KeyID, "kei-pb-000000-") {
			continue
		}
		pub, e1 := base64.RawURLEncoding.DecodeString(k.X)
		rawSig, e2 := base64.StdEncoding.DecodeString(sig.Sig)
		if e1 == nil && e2 == nil && len(pub) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(pub), pae, rawSig) {
			verified = true
			validIDs = append(validIDs, sig.KeyID)
		}
	}
	if !verified {
		return nil, errors.New("policy envelope has no signature from a trusted, active, non-revoked key")
	}
	if err := validatePayloadSchema(payloadBytes); err != nil {
		return nil, fmt.Errorf("invalid policy bundle schema: %w", err)
	}
	var payload Payload
	if err := strictJSON(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("decode policy payload: %w", err)
	}
	if payload.Schema != "kei.policy-bundle/v1" || payload.Issuer != Issuer || payload.BundleID == "" || payload.BundleVersion < 1 || payload.PolicyRevision < 1 {
		return nil, errors.New("unsupported policy bundle identity")
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
	if payload.SubjectResolution.Mode != "online" || payload.SubjectResolution.MaxCacheSeconds > 60 {
		return nil, errors.New("unsupported subject resolution mode")
	}
	if err := validatePolicyDialect(payload.PolicySet); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payloadBytes)
	return &Verified{Payload: payload, PayloadBytes: payloadBytes, Digest: fmt.Sprintf("sha256:%x", digest), KeyIDs: validIDs}, nil
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
		return errors.New("unsupported policy evaluation dialect")
	}
	return nil
}

var keyIDPattern = regexp.MustCompile(`^kei-pb-[0-9]{6}-[0-9]{2}$`)

func ParseKeySet(raw []byte) (KeySet, error) {
	var keys KeySet
	if err := strictJSON(raw, &keys); err != nil {
		return keys, err
	}
	if err := ValidateKeySet(keys); err != nil {
		return keys, err
	}
	return keys, nil
}

func ValidateKeySet(keys KeySet) error {
	if len(keys.Keys) == 0 {
		return errors.New("empty key set")
	}
	seen := map[string]bool{}
	for _, k := range keys.Keys {
		if !keyIDPattern.MatchString(k.KID) || seen[k.KID] || k.KTY != "OKP" || k.CRV != "Ed25519" || k.Use != "sig" || k.Alg != "EdDSA" || (k.Status != "next" && k.Status != "active" && k.Status != "retiring") {
			return errors.New("invalid or duplicate signing key metadata")
		}
		seen[k.KID] = true
		pub, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return errors.New("invalid signing public key")
		}
	}
	seen = map[string]bool{}
	for _, id := range keys.RevokedKeyIDs {
		if !keyIDPattern.MatchString(id) || seen[id] {
			return errors.New("invalid or duplicate revoked key id")
		}
		seen[id] = true
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

// RejectDuplicateJSON rejects ambiguous duplicate object keys before any JSON
// parser can apply last-key-wins behavior to security-sensitive signed data.
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

func dssePAE(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len([]byte(payloadType)), payloadType, len(payload), payload))
}
