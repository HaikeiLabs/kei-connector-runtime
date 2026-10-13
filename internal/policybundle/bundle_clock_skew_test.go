package policybundle

import (
	"strings"
	"testing"
	"time"
)

// A runtime clock slightly behind the catalog's must not reject a freshly
// issued v2 bundle; v2 tolerates the same bounded skew as v1.
func TestValidateV2AllowsBoundedIssuedAtClockSkew(t *testing.T) {
	previous := schemaValidatorV2
	SetV2SchemaValidator(v2SchemaValidator(t))
	t.Cleanup(func() { SetV2SchemaValidator(previous) })
	now := time.Date(2026, 10, 12, 12, 10, 0, 0, time.UTC)

	for name, tc := range map[string]struct {
		ahead  time.Duration
		accept bool
	}{
		"issued 1s ahead":            {ahead: time.Second, accept: true},
		"issued at the skew limit":   {ahead: MaxIssuedAtClockSkew, accept: true},
		"issued 10 minutes ahead":    {ahead: 10 * time.Minute, accept: false},
		"issued just past the limit": {ahead: MaxIssuedAtClockSkew + time.Millisecond, accept: false},
	} {
		t.Run(name, func(t *testing.T) {
			raw := mustJSON(t, v2BundleDoc(now.Add(tc.ahead)))
			_, err := ValidateV2(raw, v2Installation, v2Org, v2Workspace, 1, now)
			if tc.accept && err != nil {
				t.Fatalf("bundle issued %s ahead rejected: %v", tc.ahead, err)
			}
			if !tc.accept && (err == nil || !strings.Contains(err.Error(), "issued too far in the future")) {
				t.Fatalf("bundle issued %s ahead: err = %v, want issued too far in the future", tc.ahead, err)
			}
		})
	}
}

func TestValidateV1IssuedAtClockSkewUnchanged(t *testing.T) {
	inst, org, ws := audience()
	issuedAt := time.Date(2026, 9, 28, 16, 0, 0, 0, time.UTC)
	if _, err := Validate(fixtureBundle(t), inst, org, ws, 0, issuedAt.Add(-5*time.Minute)); err != nil {
		t.Fatalf("v1 bundle issued 5m ahead rejected: %v", err)
	}
	if _, err := Validate(fixtureBundle(t), inst, org, ws, 0, issuedAt.Add(-5*time.Minute-time.Millisecond)); err == nil {
		t.Fatal("v1 bundle issued more than 5m ahead accepted")
	}
}

// An accepted bundle issued slightly ahead must also be usable at once:
// Store.Check gates v2 on SubjectSnapshotFresh, which shares the skew bound.
func TestV2StoreCheckActiveForBundleIssuedWithinClockSkew(t *testing.T) {
	previous := schemaValidatorV2
	SetV2SchemaValidator(v2SchemaValidator(t))
	t.Cleanup(func() { SetV2SchemaValidator(previous) })
	now := time.Date(2026, 10, 12, 12, 10, 0, 0, time.UTC)
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(mustJSON(t, v2BundleDoc(now.Add(300*time.Millisecond))), v2Installation, v2Org, v2Workspace, now); err != nil {
		t.Fatalf("activate v2 bundle issued 300ms ahead: %v", err)
	}
	verified, state, err := store.Check(v2Installation, v2Org, v2Workspace, now)
	if verified == nil || state != Active || err != nil {
		t.Fatalf("check verified=%v state=%s err=%v", verified != nil, state, err)
	}
	if verified.SubjectSnapshotFresh(now.Add(-MaxIssuedAtClockSkew)) {
		t.Fatal("snapshot fresh for a clock further behind issued_at than the skew bound")
	}
}
