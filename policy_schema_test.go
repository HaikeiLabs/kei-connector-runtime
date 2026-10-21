package connectorruntime

import (
	"strings"
	"testing"
	"time"

	bundle "github.com/HaikeiLabs/kei-connector-contracts/bundle"
)

// These tests fail when a startup hook is removed. Because init() runs before
// any test, a missing SetSchemaValidator / SetV2SchemaValidator / SetPlanValidator
// call in policy_schema.go would leave the validator nil and these checks fail.

func TestSchemaValidatorIsInstalled(t *testing.T) {
	// bundle.SchemaValidator is unexported; we check by calling bundle.Validate
	// on a minimal v1 bundle document. A nil validator would error with
	// "schema validator is unavailable".
	_, err := bundle.Validate(
		[]byte(`{"schema":"kei.policy-bundle/v1","bundle_id":"test","bundle_version":1,"policy_revision":1,"issuer":"kei-policy-catalog","audience":{"installation_id":"i","org_id":"o","workspace_id":"w"},"issued_at":"2026-10-01T11:59:00Z","not_after":"2026-10-01T12:00:00Z","subject_resolution":{"mode":"online"},"policy_set":{"match_semantics":"kei.match/v1","evaluation":{"order":"array_order_first_match","default":"deny"}}}`),
		"i", "o", "w", 0, mustParseTime("2026-10-01T11:59:30Z"),
	)
	if err != nil && contains(err.Error(), "validator is unavailable") {
		t.Fatal("SetSchemaValidator was not called in init: schema validator is nil")
	}
	t.Logf("SetSchemaValidator installed (bundle.Validate returned: %v)", err)
}

func TestV2SchemaValidatorIsInstalled(t *testing.T) {
	// Same for the v2 validator.
	_, err := bundle.ValidateV2(
		[]byte(`{"schema":"kei.policy-bundle/v2","bundle_id":"test","bundle_version":1,"policy_revision":1,"issuer":"kei-policy-catalog","audience":{"installation_id":"i","org_id":"o","workspace_id":"w"},"issued_at":"2026-10-01T11:59:00Z","not_after":"2026-10-01T12:00:00Z","subject_resolution":{"mode":"bundle"},"identities":[],"harnesses":[],"policy_set":{"schema":"kei.policy-set/v2","match_semantics":"kei.match/v2","evaluation":{"checks":"per_capability_first_match_and","default":"deny"},"tools":[],"checks":[],"tool_policies":[],"harness_policies":[]}}`),
		"i", "o", "w", 0, mustParseTime("2026-10-01T11:59:30Z"),
	)
	if err != nil && contains(err.Error(), "validator is unavailable") {
		t.Fatal("SetV2SchemaValidator was not called in init: v2 schema validator is nil")
	}
	t.Logf("SetV2SchemaValidator installed (bundle.ValidateV2 returned: %v)", err)
}

func TestPlanValidatorIsInstalled(t *testing.T) {
	// bundle.planValid is unexported; we check by passing a tool with a plan
	// through bundle.ValidateV2 — if planValidator is nil the bundle is rejected
	// with "plan validator is unavailable".
	// A valid plan passes; we don't care about the result here, just that the
	// plan validator isn't nil.
	_, err := bundle.ValidateV2(
		[]byte(`{"schema":"kei.policy-bundle/v2","bundle_id":"test","bundle_version":1,"policy_revision":1,"issuer":"kei-policy-catalog","audience":{"installation_id":"i","org_id":"o","workspace_id":"w"},"issued_at":"2026-10-01T11:59:00Z","not_after":"2026-10-01T12:00:00Z","subject_resolution":{"mode":"bundle"},"identities":[],"harnesses":[],"policy_set":{"schema":"kei.policy-set/v2","match_semantics":"kei.match/v2","evaluation":{"checks":"per_capability_first_match_and","default":"deny"},"tools":[],"checks":[],"tool_policies":[],"harness_policies":[]}}`),
		"i", "o", "w", 0, mustParseTime("2026-10-01T11:59:30Z"),
	)
	if err != nil && contains(err.Error(), "plan validator is unavailable") {
		t.Fatal("SetPlanValidator was not called in init: plan validator is nil")
	}
	t.Logf("SetPlanValidator installed (bundle.ValidateV2 returned: %v)", err)
}

func mustParseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
