package policybundle

import (
	"encoding/json"
	"slices"
	"testing"
	"time"
)

func TestBundleMembershipsReturnsNilForModeOnline(t *testing.T) {
	v := &Verified{Payload: Payload{SubjectResolution: struct {
		Mode            string `json:"mode"`
		MaxCacheSeconds int    `json:"max_cache_seconds"`
	}{Mode: "online"}}}
	v.Payload.Schema = "kei.policy-bundle/v2"
	if m := BundleMemberships(v); m != nil {
		t.Fatal("expected nil memberships for mode=online bundle")
	}
}

func TestBundleMembershipsReturnsNilForEmptyIdentities(t *testing.T) {
	v := &Verified{Payload: Payload{SubjectResolution: struct {
		Mode            string `json:"mode"`
		MaxCacheSeconds int    `json:"max_cache_seconds"`
	}{Mode: "bundle"}}}
	v.Payload.Schema = "kei.policy-bundle/v2"
	if m := BundleMemberships(v); m != nil {
		t.Fatal("expected nil memberships when identities slice is empty")
	}
}

func TestBundleMembershipsLookup(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name     string
		userID   string
		expected struct {
			groups  []string
			roles   []string
			granted bool
			known   bool
		}
	}{
		{
			name:   "linked identity grants groups and roles",
			userID: "u-alice",
			expected: struct {
				groups  []string
				roles   []string
				granted bool
				known   bool
			}{groups: []string{"members", "admins"}, roles: []string{"org:admin"}, granted: true, known: true},
		},
		{
			name:   "pending identity is known but not granted",
			userID: "u-bob",
			expected: struct {
				groups  []string
				roles   []string
				granted bool
				known   bool
			}{groups: []string{"members"}, roles: nil, granted: false, known: true},
		},
		{
			name:   "revoked identity is known but not granted",
			userID: "u-carol",
			expected: struct {
				groups  []string
				roles   []string
				granted bool
				known   bool
			}{groups: []string{"former"}, roles: nil, granted: false, known: true},
		},
		{
			name:   "cross-workspace identity is known but not granted",
			userID: "u-dave",
			expected: struct {
				groups  []string
				roles   []string
				granted bool
				known   bool
			}{groups: nil, roles: nil, granted: false, known: true},
		},
		{
			name:   "expired identity is not known",
			userID: "u-expired",
			expected: struct {
				groups  []string
				roles   []string
				granted bool
				known   bool
			}{groups: nil, roles: nil, granted: false, known: false},
		},
		{
			name:   "unknown userID is not known",
			userID: "u-unknown",
			expected: struct {
				groups  []string
				roles   []string
				granted bool
				known   bool
			}{groups: nil, roles: nil, granted: false, known: false},
		},
	}

	identities := []Identity{
		{
			UserID:     "u-alice",
			Status:     SubjectLinked,
			Groups:     []string{"members", "admins"},
			OrgRoles:   []string{"org:admin"},
			ExpireTime: time.Time{},
		},
		{
			UserID: "u-bob",
			Status: SubjectPending,
			Groups: []string{"members"},
		},
		{
			UserID: "u-carol",
			Status: SubjectRevoked,
			Groups: []string{"former"},
		},
		{
			UserID: "u-dave",
			Status: SubjectCrossWorkspace,
		},
		{
			UserID:     "u-expired",
			Status:     SubjectLinked,
			Groups:     []string{"members"},
			ExpireTime: now.Add(-1 * time.Hour),
		},
	}

	v := &Verified{Payload: Payload{
		SubjectResolution: struct {
			Mode            string `json:"mode"`
			MaxCacheSeconds int    `json:"max_cache_seconds"`
		}{Mode: "bundle"},
		Identities: identities,
	}}

	v.Payload.Schema = "kei.policy-bundle/v2"
	m := BundleMembershipsAt(v, now)
	if m == nil {
		t.Fatal("expected non-nil memberships for mode=bundle with identities")
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			groups, roles, granted, known := m.Lookup(tc.userID)
			if !stringSliceEqual(groups, tc.expected.groups) {
				t.Errorf("groups = %v, want %v", groups, tc.expected.groups)
			}
			if !stringSliceEqual(roles, tc.expected.roles) {
				t.Errorf("roles = %v, want %v", roles, tc.expected.roles)
			}
			if granted != tc.expected.granted {
				t.Errorf("granted = %v, want %v", granted, tc.expected.granted)
			}
			if known != tc.expected.known {
				t.Errorf("known = %v, want %v", known, tc.expected.known)
			}
		})
	}
}

func TestLookupIdentityUsesBundleKeysAndFailsClosed(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	v := &Verified{Payload: Payload{
		SubjectResolution: struct {
			Mode            string `json:"mode"`
			MaxCacheSeconds int    `json:"max_cache_seconds"`
		}{Mode: "bundle", MaxCacheSeconds: 60},
		Identities: []Identity{
			{Source: "discord", ExternalID: "alice", UserID: "u-alice", Status: SubjectLinked},
			{Source: "discord", ExternalID: "pending", UserID: "u-pending", Status: SubjectPending},
			{Source: "discord", ExternalID: "expired", UserID: "u-expired", Status: SubjectLinked, ExpireTime: now},
		},
	}}
	if got, ok := v.LookupIdentity("discord", "alice", now); !ok || got.UserID != "u-alice" || got.Status != SubjectLinked {
		t.Fatalf("linked identity = %+v, %v", got, ok)
	}
	if got, ok := v.LookupIdentity("discord", "pending", now); !ok || got.Status != SubjectPending {
		t.Fatalf("pending identity = %+v, %v", got, ok)
	}
	for _, key := range [][2]string{{"discord", "missing"}, {"slack", "alice"}, {"discord", "expired"}, {"", "alice"}, {"discord", ""}} {
		if got, ok := v.LookupIdentity(key[0], key[1], now); ok {
			t.Errorf("LookupIdentity(%q,%q) = %+v, true; want fail closed", key[0], key[1], got)
		}
	}
	v.Payload.Identities = append(v.Payload.Identities, Identity{Source: "discord", ExternalID: "alice", UserID: "u-substitution", Status: SubjectLinked})
	if got, ok := v.LookupIdentity("discord", "alice", now); ok {
		t.Fatalf("duplicate identity mapping selected %+v", got)
	}
	v.Payload.SubjectResolution.Mode = "online"
	if got, ok := v.LookupIdentity("discord", "pending", now); ok {
		t.Fatalf("online mode returned identity %+v", got)
	}
}

// A v2 bundle resolves subjects from its own identities snapshot; the only
// supported subject_resolution mode is "bundle" (HAI-622-F removed the v1
// "online" mode with the v1 bundle).
func TestBundleValidateAcceptsBundleModeAndRejectsAnyOtherMode(t *testing.T) {
	SetV2SchemaValidator(func([]byte) error { return nil })
	t.Cleanup(func() { SetV2SchemaValidator(nil) })
	now := time.Now().UTC()
	build := func(mode string) []byte {
		doc := v2BundleDoc(now)
		doc["subject_resolution"] = map[string]any{"mode": mode, "max_cache_seconds": 60}
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	v, err := Validate(build("bundle"), v2Installation, v2Org, v2Workspace, 1, now)
	if err != nil {
		t.Fatalf("Validate bundle mode: %v", err)
	}
	if v.Payload.SubjectResolution.Mode != "bundle" || v.Payload.SubjectResolution.MaxCacheSeconds != 60 {
		t.Fatalf("subject_resolution = %+v", v.Payload.SubjectResolution)
	}
	for _, mode := range []string{"online", "hybrid"} {
		if _, err := Validate(build(mode), v2Installation, v2Org, v2Workspace, 1, now); err != ErrBundleUnsupported {
			t.Fatalf("mode %q: err = %v, want ErrBundleUnsupported", mode, err)
		}
	}
}

// stringSliceEqual compares two membership lists as sets of values: a v2 bundle
// aggregates an identity's groups and roles through a map, so Lookup returns
// them in no fixed order.
func stringSliceEqual(a, b []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
}

func mustRawMessage(t *testing.T, s string) json.RawMessage {
	t.Helper()
	return json.RawMessage(s)
}
