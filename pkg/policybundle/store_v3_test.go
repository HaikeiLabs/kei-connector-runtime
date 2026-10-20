package policybundle

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

// v3EnvelopeWithVersion returns v3Envelope(now) with bundle_version set to
// the given version and bundle_id to a deterministic UUID-like string.
func v3EnvelopeWithVersion(now time.Time, version int64, bundleID string) map[string]any {
	doc := v3Envelope(now)
	doc["bundle_version"] = version
	doc["bundle_id"] = bundleID
	return doc
}

// TestActivateV3BadPolicyNoPreviousFails verifies that activating a v3 bundle
// with a corrupt policy payload returns an error when there is no previously
// good policy (fail-closed per ADR-039).
func TestActivateV3BadPolicyNoPreviousFails(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	doc := v3EnvelopeWithVersion(now, 1, "bundle-1")

	// Corrupt the policy payload: wrong digest.
	payloads := doc["payloads"].(map[string]any)
	payloads["policy"] = map[string]any{
		"schema": "policy-bundle-v1",
		"digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"data": map[string]any{
			"deny_all": true,
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	// ActivateV3 does not exist yet — this should fail to compile.
	err = store.ActivateV3(raw, "inst-v3", "org-v3", "ws-v3", now)
	if err == nil {
		t.Fatal("expected error when activating bad policy payload with no previous good copy")
	}
}

// TestActivateV3BadPolicyWithPreviousKeepsOld verifies that activating a v3
// bundle with a corrupt policy payload succeeds when a previous good policy
// exists in the store (non-fatal, keeps last-good).
func TestActivateV3BadPolicyWithPreviousKeepsOld(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

	// First, activate a valid v3 bundle (version 1).
	goodDoc := v3EnvelopeWithVersion(now, 1, "bundle-good-1")
	goodRaw, err := json.Marshal(goodDoc)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ActivateV3(goodRaw, "inst-v3", "org-v3", "ws-v3", now); err != nil {
		t.Fatalf("ActivateV3 good bundle: %v", err)
	}

	// Now activate a bundle with a bad policy payload (version 2, so it passes
	// rollback protection).
	badDoc := v3EnvelopeWithVersion(now, 2, "bundle-bad-2")
	payloads := badDoc["payloads"].(map[string]any)
	payloads["policy"] = map[string]any{
		"schema": "policy-bundle-v1",
		"digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		"data": map[string]any{
			"deny_all": true,
		},
	}
	badRaw, err := json.Marshal(badDoc)
	if err != nil {
		t.Fatal(err)
	}

	// This should NOT error because the store has a previous good policy copy.
	if err := store.ActivateV3(badRaw, "inst-v3", "org-v3", "ws-v3", now); err != nil {
		t.Fatalf("ActivateV3 with previous good copy should not error: %v", err)
	}
}
