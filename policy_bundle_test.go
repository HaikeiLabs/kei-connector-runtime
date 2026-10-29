package connectorruntime

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

// The vendored canonical v2 example payload is addressed to inst-v2 / org-v2 /
// ws-v2 at bundle version 2, issued 2026-10-05T12:00Z and valid for 11 hours.
const (
	canonicalV2Installation = "inst-v2"
	canonicalV2Org          = "org-v2"
	canonicalV2Workspace    = "ws-v2"
)

func canonicalV2Bundle(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("docs/contracts/examples/policy-bundle-v2.payload.example.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestValidateUnsignedCanonicalBundleAndDigest(t *testing.T) {
	raw := canonicalV2Bundle(t)
	now := time.Date(2026, 10, 5, 12, 30, 0, 0, time.UTC)
	verified, err := policybundle.Validate(raw, canonicalV2Installation, canonicalV2Org, canonicalV2Workspace, 1, now)
	if err != nil {
		t.Fatalf("validate unsigned canonical bundle: %v", err)
	}
	want := fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
	if verified.Payload.BundleVersion != 2 || verified.Digest != want || string(verified.PayloadBytes) != string(raw) {
		t.Fatalf("unsigned bundle version=%d digest=%s want=%s", verified.Payload.BundleVersion, verified.Digest, want)
	}
	if strings.Contains(string(raw), `"signatures"`) {
		t.Fatal("canonical JSON payload unexpectedly requires or carries signatures")
	}
}

func TestValidateUnsignedBundleRejectsAudienceRollbackExpirySchemaAndDuplicateKeys(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 30, 0, 0, time.UTC)
	base := canonicalV2Bundle(t)
	validate := func(raw []byte, installation string, highest int64, at time.Time) error {
		_, err := policybundle.Validate(raw, installation, canonicalV2Org, canonicalV2Workspace, highest, at)
		return err
	}
	if err := validate(base, "other-installation", 1, now); err == nil {
		t.Fatal("accepted mismatched audience")
	}
	if err := validate(base, canonicalV2Installation, 2, now); err == nil {
		t.Fatal("accepted equal bundle version")
	}
	if err := validate(base, canonicalV2Installation, 1, now.Add(12*time.Hour)); !errors.Is(err, policybundle.ErrBundleExpired) {
		t.Fatalf("expiry error=%v", err)
	}
	trimmed := bytes.TrimRight(base, " \n\t")
	unknown := append(append([]byte(nil), trimmed[:len(trimmed)-1]...), []byte(`,"unexpected":true}`)...)
	if err := validate(unknown, canonicalV2Installation, 1, now); err == nil {
		t.Fatal("accepted unknown schema field")
	}
	duplicate := bytes.Replace(base, []byte(`"bundle_version": 2`), []byte(`"bundle_version": 2, "bundle_version": 3`), 1)
	if bytes.Equal(duplicate, base) {
		t.Fatal("fixture does not contain the bundle_version text the duplicate-key case rewrites")
	}
	if err := validate(duplicate, canonicalV2Installation, 1, now); err == nil {
		t.Fatal("accepted duplicate security field")
	}
}
