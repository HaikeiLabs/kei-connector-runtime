// Package policybundle defines the wire types and validation for Kei policy
// bundles. It is public so kei-cli can decode and inspect a bundle with the
// same types and the same checks the runtime enforces.
//
// The package is a thin layer over github.com/HaikeiLabs/kei-connector-contracts/bundle:
// identical wire types are aliased to the shared contracts types. Payload is
// kept local because it carries an extra AccessGrants field (HAI-615) that the
// shared contracts type does not yet carry. Validate and ValidateV2 are kept
// local for the same reason: they decode into the local Payload.
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

	bundle "github.com/HaikeiLabs/kei-connector-contracts/bundle"
	"github.com/HaikeiLabs/kei-connector-contracts/harnessmatch"
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// ContentType is the media type for a v1 policy bundle: the legacy model the
// catalog still folds its v2 policy set into, and the one the runtime still
// accepts. Kept for callers that check the v1 constant.
const ContentType = bundle.ContentType

// ContentTypeV2 is the media type for the current v2 policy bundle.
const ContentTypeV2 = bundle.ContentTypeV2

// Issuer is the expected issuer claim in every valid bundle.
const Issuer = bundle.Issuer

// MaxIssuedAtClockSkew is how far a bundle's issued_at may be ahead of the
// runtime clock. The catalog stamps issued_at with its own clock, which can
// lead a runtime host by a few hundred milliseconds.
const MaxIssuedAtClockSkew = bundle.MaxIssuedAtClockSkew

var (
	ErrBundleExpired        = bundle.ErrBundleExpired
	ErrBundleUnsupported    = bundle.ErrBundleUnsupported
	ErrSubjectSnapshotStale = bundle.ErrSubjectSnapshotStale
)

// Audience identifies the installation a bundle is scoped to.
type Audience = bundle.Audience

// Identity is one known user in a bundle with subject_resolution.mode=bundle.
type Identity = bundle.Identity

// Harness is one registered coding-agent harness (ADR-029 §2).
type Harness = bundle.Harness

// AccessGrant is one live access grant in a v2 bundle (ADR-038 §2, HAI-615):
// a JIT grant that opens one typed target for one principal until it ends.
// The principal is "<kind>:<id>" ("user:<id>" or "agent:<id>") and the target
// is a typed target ("tool:<name>"), the strings the shared policy package
// matches. A grant's reason, its granter and its approver stay in the
// catalog: only what a decision needs travels in a bundle.
type AccessGrant struct {
	Principal  string    `json:"principal"`
	Target     string    `json:"target"`
	ExpireTime time.Time `json:"expire_time"`
}

// Payload is the signed-envelope body of a policy bundle.
// It embeds the shared contracts Payload and adds the runtime-specific
// AccessGrants projection (HAI-615).
type Payload struct {
	bundle.Payload
	// AccessGrants is the v2-only projection of the workspace's live access
	// grants (ADR-038 §2, HAI-615). A grant opens one typed target for one
	// principal until it ends. It never overrides a deny.
	AccessGrants []AccessGrant `json:"access_grants,omitempty"`
}

// AgentModelProfile is one agent's effective model profile in a v2 bundle
// (ADR-035 §6). Status is the profile's catalog status; only active permits.
type AgentModelProfile = bundle.AgentModelProfile

// InstallationSubject is the installation's principal as the catalog resolved
// it (HAI-433): the installation creator, their email, and their effective
// group names. Only kei.policy-bundle/v2 carries it; harness renderers apply
// user:, email: and group: harness_policies sources against it.
type InstallationSubject = bundle.InstallationSubject

// Verified wraps a successfully validated bundle together with its raw bytes
// and digest.
type Verified struct {
	Payload      Payload
	PayloadBytes []byte
	Digest       string
}

// toBundle returns a *bundle.Verified backed by this Verified's data, for
// delegating shared evaluation logic to the contracts package.
func (v *Verified) toBundle() *bundle.Verified {
	if v == nil {
		return nil
	}
	return &bundle.Verified{
		Payload:      v.Payload.Payload,
		PayloadBytes: v.PayloadBytes,
		Digest:       v.Digest,
	}
}

// Validate checks an unsigned catalog bundle retrieved over the authenticated
// HTTPS runtime-control-plane connection. The digest binds the exact received
// bytes to the catalog ETag and persisted state; it is not a signature.
//
// The function is kept local because it decodes into the local Payload type,
// which carries the runtime-specific AccessGrants field. The shared
// structural validation is delegated to bundle.Validate; the local function
// then decodes the extra field from the same bytes.
func Validate(bundleBytes []byte, installationID, orgID, workspaceID string, highestVersion int64, now time.Time) (*Verified, error) {
	if len(bundleBytes) == 0 {
		return nil, errors.New("empty policy bundle")
	}
	if err := bundle.RejectDuplicateJSON(bundleBytes); err != nil {
		return nil, err
	}
	var identity struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(bundleBytes, &identity); err != nil {
		return nil, fmt.Errorf("decode policy bundle identity: %w", err)
	}
	if identity.Schema == "kei.policy-bundle/v2" {
		return ValidateV2(bundleBytes, installationID, orgID, workspaceID, highestVersion, now)
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
	if payload.IssuedAt.After(now.Add(MaxIssuedAtClockSkew)) {
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

var (
	schemaValidator   func([]byte) error
	schemaValidatorV2 func([]byte) error
)

// SetSchemaValidator installs the v1 bundle JSON Schema validator. It
// delegates to the shared contracts package so both this package and
// bundle.Validate use the same validator.
func SetSchemaValidator(v func([]byte) error) {
	schemaValidator = v
	bundle.SetSchemaValidator(v)
}

// SetV2SchemaValidator installs the v2 bundle JSON Schema validator. It
// delegates to the shared contracts package so both this package and
// bundle.ValidateV2 use the same validator.
func SetV2SchemaValidator(v func([]byte) error) {
	schemaValidatorV2 = v
	bundle.SetV2SchemaValidator(v)
}

// ValidateV2 validates the ADR-035 envelope without making it active in the
// v1 Store/PEP path. Activation remains disabled until the v2 evaluator and
// connector preflight are wired together.
func ValidateV2(bundleBytes []byte, installationID, orgID, workspaceID string, highestVersion int64, now time.Time) (*Verified, error) {
	if len(bundleBytes) == 0 {
		return nil, errors.New("empty policy bundle")
	}
	if err := bundle.RejectDuplicateJSON(bundleBytes); err != nil {
		return nil, err
	}
	if schemaValidatorV2 == nil {
		return nil, errors.New("policy bundle v2 schema validator is unavailable")
	}
	if err := schemaValidatorV2(bundleBytes); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "additional properties") {
			return nil, fmt.Errorf("%w: closed v2 schema rejected unknown field", ErrBundleUnsupported)
		}
		return nil, fmt.Errorf("invalid policy bundle v2 schema: %w", err)
	}
	var payload Payload
	if err := strictJSON(bundleBytes, &payload); err != nil {
		return nil, fmt.Errorf("decode policy bundle v2: %w", err)
	}
	if payload.Schema != "kei.policy-bundle/v2" || payload.Issuer != Issuer || payload.BundleID == "" || payload.BundleVersion < 1 || payload.PolicyRevision < 1 {
		return nil, errors.New("invalid policy bundle v2 identity")
	}
	if payload.Audience.InstallationID != installationID || payload.Audience.OrgID != orgID || payload.Audience.WorkspaceID != workspaceID {
		return nil, errors.New("policy bundle v2 audience mismatch")
	}
	if payload.BundleVersion <= highestVersion {
		return nil, errors.New("policy bundle v2 version rollback or replay")
	}
	if payload.IssuedAt.After(now.Add(MaxIssuedAtClockSkew)) {
		return nil, errors.New("policy bundle v2 issued too far in the future")
	}
	if !now.Before(payload.NotAfter) {
		return nil, ErrBundleExpired
	}
	if payload.NotAfter.After(payload.IssuedAt.Add(24*time.Hour)) || !payload.NotAfter.After(payload.IssuedAt) {
		return nil, errors.New("invalid policy bundle v2 validity window")
	}
	if payload.SubjectResolution.Mode != "bundle" || payload.Identities == nil {
		return nil, ErrBundleUnsupported
	}
	if err := validatePolicySetV2(payload.PolicySet); err != nil {
		return nil, err
	}
	if err := validateHarnesses(payload.Harnesses, payload.HarnessMatchSemantics); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBundleUnsupported, err)
	}
	digest := sha256.Sum256(bundleBytes)
	return &Verified{Payload: payload, PayloadBytes: append([]byte(nil), bundleBytes...), Digest: fmt.Sprintf("sha256:%x", digest)}, nil
}

func validatePolicySetV2(raw json.RawMessage) error {
	var v struct {
		Schema         string `json:"schema"`
		MatchSemantics string `json:"match_semantics"`
		Evaluation     struct {
			Checks  string `json:"checks"`
			Default string `json:"default"`
		} `json:"evaluation"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	if v.Schema != "kei.policy-set/v2" || v.MatchSemantics != "kei.match/v2" || v.Evaluation.Checks != "per_capability_first_match_and" || v.Evaluation.Default != "deny" {
		return ErrBundleUnsupported
	}
	var set v2PolicySet
	if err := strictJSON(raw, &set); err != nil {
		return ErrBundleUnsupported
	}
	for _, tool := range set.Tools {
		if tool.Route.ConnectorBinding != nil && len(tool.Plan) > 0 {
			if err := ValidateV2Plan(tool); err != nil {
				return ErrBundleUnsupported
			}
		}
	}
	return nil
}

func validatePayloadSchema(raw []byte) error {
	if err := bundle.RejectDuplicateJSON(raw); err != nil {
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
	if err := bundle.RejectDuplicateJSON(raw); err != nil {
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
// Delegates to the shared contracts implementation.
var RejectDuplicateJSON = bundle.RejectDuplicateJSON
