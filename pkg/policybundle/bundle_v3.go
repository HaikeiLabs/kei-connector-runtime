package policybundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// v3 schema constant.
const ContentTypeV3 = "application/vnd.kei.policy-bundle.v3+json"

// V3BundleResult is the return type of ValidateV3: one field per payload.
// Each payload pointer is nil when the corresponding payload is corrupt or
// absent. The Error fields carry safe reason codes (never the raw payload).
// Version carries the bundle_version from the envelope for caller use
// (e.g. against the Kei-Policy-Bundle-Version response header).
type V3BundleResult struct {
	Policy      *PolicyPayloadData
	Connectors  *ConnectorsPayloadData
	HarnessMeta *HarnessMetaPayloadData
	ModelInfo   *ModelInfoPayloadData

	PolicyError      string
	ConnectorsError  string
	HarnessMetaError string
	ModelInfoError   string

	Version int64
}

// PolicyPayloadData is the deserialised policy-set content carried inside a
// policy-bundle-v1 payload.
type PolicyPayloadData struct {
	Raw json.RawMessage
}

// ConnectorsPayloadData is the deserialised connector-tool content carried
// inside a connectors-v1 payload.
type ConnectorsPayloadData struct {
	Raw json.RawMessage
}

// HarnessMetaPayloadData is the deserialised harness metadata content carried
// inside a harness-meta-v1 payload.
type HarnessMetaPayloadData struct {
	Raw json.RawMessage
}

// ModelInfoPayloadData is the deserialised model-profile content carried inside
// a model-info-v1 payload.
type ModelInfoPayloadData struct {
	Raw json.RawMessage
}

// ----- v3 envelope types (local; independent of the catalog's) -----

type v3Audience struct {
	InstallationID string `json:"installation_id"`
	OrgID          string `json:"org_id"`
	WorkspaceID    string `json:"workspace_id"`
}

type v3FourPayloadBundle struct {
	Schema   string       `json:"schema"`
	BundleID string       `json:"bundle_id"`
	Version  int64        `json:"bundle_version"`
	Revision int64        `json:"policy_revision"`
	Issuer   string       `json:"issuer"`
	Audience v3Audience   `json:"audience"`
	IssuedAt time.Time    `json:"issued_at"`
	NotAfter time.Time    `json:"not_after"`
	Payloads v3PayloadSet `json:"payloads"`
}

type v3PayloadSet struct {
	Policy      json.RawMessage `json:"policy"`
	Connectors  json.RawMessage `json:"connectors"`
	HarnessMeta json.RawMessage `json:"harness_meta"`
	ModelInfo   json.RawMessage `json:"model_info"`
}

// ----- per-payload envelope (schema + digest + data) -----

type v3PayloadEnvelope struct {
	Schema string          `json:"schema"`
	Digest string          `json:"digest"`
	Data   json.RawMessage `json:"data"`
}

// SchemaVersion returns the four-payload bundle schema identifier.
func (v *v3FourPayloadBundle) SchemaVersion() string { return v.Schema }

// ValidateV3 validates a v3 four-payload bundle per ADR-039. Envelope-level
// failures (bad JSON, expired, audience mismatch, rollback) return an error.
// Per-payload failures are reported in the returned V3BundleResult: the
// payload pointer is nil and the corresponding Error field carries a safe
// reason code (never the payload content). The caller decides whether a bad
// policy payload is fail-closed or keep-last-good.
func ValidateV3(bundleBytes []byte, installationID, orgID, workspaceID string, highestVersion int64, now time.Time) (*V3BundleResult, error) {
	if len(bundleBytes) == 0 {
		return nil, fmt.Errorf("empty policy bundle")
	}

	var env v3FourPayloadBundle
	if err := json.Unmarshal(bundleBytes, &env); err != nil {
		return nil, fmt.Errorf("decode v3 envelope: %w", err)
	}
	if env.Schema != "kei.policy-bundle/v3" {
		return nil, fmt.Errorf("%w: expected v3 schema, got %q", ErrBundleUnsupported, env.Schema)
	}

	// Validate envelope identity and freshness.
	if env.Issuer != Issuer || env.BundleID == "" || env.Version < 1 || env.Revision < 1 {
		return nil, fmt.Errorf("invalid v3 bundle identity")
	}
	if env.Audience.InstallationID != installationID || env.Audience.OrgID != orgID || env.Audience.WorkspaceID != workspaceID {
		return nil, fmt.Errorf("v3 bundle audience mismatch")
	}
	if env.Version <= highestVersion {
		return nil, fmt.Errorf("v3 bundle version rollback or replay")
	}
	if env.IssuedAt.After(now.Add(MaxIssuedAtClockSkew)) {
		return nil, fmt.Errorf("v3 bundle issued too far in the future")
	}
	if !now.Before(env.NotAfter) {
		return nil, ErrBundleExpired
	}
	if env.NotAfter.After(env.IssuedAt.Add(24*time.Hour)) || !env.NotAfter.After(env.IssuedAt) {
		return nil, fmt.Errorf("invalid v3 bundle validity window")
	}

	result := &V3BundleResult{
		Version: env.Version,
	}

	// Validate policy payload — failure is reported in PolicyError; caller
	// decides fail-closed vs keep-last-good.
	result.Policy, result.PolicyError = validateSinglePayload[PolicyPayloadData](env.Payloads.Policy, "policy-bundle-v1")

	// Validate connectors payload — failure is reported, not fatal.
	result.Connectors, result.ConnectorsError = validateSinglePayload[ConnectorsPayloadData](env.Payloads.Connectors, "connectors-v1")

	// Validate harness-meta payload — failure is reported, not fatal.
	result.HarnessMeta, result.HarnessMetaError = validateSinglePayload[HarnessMetaPayloadData](env.Payloads.HarnessMeta, "harness-meta-v1")

	// Validate model-info payload — failure is reported, not fatal.
	result.ModelInfo, result.ModelInfoError = validateSinglePayload[ModelInfoPayloadData](env.Payloads.ModelInfo, "model-info-v1")

	return result, nil
}

// validateSinglePayload deserialises and digest-validates one payload envelope.
// On success it returns the payload data. On failure it returns nil and a safe
// reason code (never the payload content).
func validateSinglePayload[T any](raw json.RawMessage, expectedSchema string) (*T, string) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, "payload_missing"
	}

	var env v3PayloadEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, "payload_invalid_json"
	}
	if env.Schema != expectedSchema {
		return nil, fmt.Sprintf("payload_schema_mismatch: got %q", env.Schema)
	}
	if env.Digest == "" {
		return nil, "payload_digest_missing"
	}
	if len(env.Data) == 0 {
		return nil, "payload_data_empty"
	}

	// Verify digest.
	computed := sha256.Sum256(env.Data)
	want := "sha256:" + hex.EncodeToString(computed[:])
	if env.Digest != want {
		return nil, "payload_digest_mismatch"
	}

	var v T
	if err := json.Unmarshal(env.Data, &v); err != nil {
		return nil, "payload_data_invalid"
	}
	return &v, ""
}
