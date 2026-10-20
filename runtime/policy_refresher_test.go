package runtime_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	connectorruntime "github.com/HaikeiLabs/kei-connector-runtime"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

func TestStartPolicyRefresherNoopWhenNotRuntime(t *testing.T) {
	stop := keiruntime.StartPolicyRefresher(
		context.Background(),
		fakePolicyConfig{isRuntime: false},
		func() (*keiruntime.Identity, error) { t.Error("whoami called"); return nil, nil },
		func(*keiruntime.Identity) error { t.Error("sync called"); return nil },
		nil, nil, nil, nil,
	)
	stop() // must not block
}

func TestStartPolicyRefresherStopCancels(t *testing.T) {
	catalog := &fakePolicyCatalog{body: unsignedExampleBundle(t, time.Now().UTC())}
	server := httptest.NewServer(catalog)
	defer server.Close()
	dir := t.TempDir()
	cfg := policyTestConfig(server.URL, dir)

	whoami := func() (*keiruntime.Identity, error) {
		return &keiruntime.Identity{ID: "test-id", OrgID: "test-org", WorkspaceID: strPtr("test-ws")}, nil
	}
	syncFn := func(identity *keiruntime.Identity) error {
		return connectorruntime.SyncPolicyBundle(context.Background(), cfg, &connectorruntime.RuntimeIdentity{
			ID: identity.ID, OrgID: identity.OrgID, WorkspaceID: identity.WorkspaceID,
		}, 10*time.Second)
	}

	stop := keiruntime.StartPolicyRefresher(
		context.Background(), cfg, whoami, syncFn,
		connectorruntime.IsRuntimeRevocation,
		func() { connectorruntime.RevokePolicyState(cfg) },
		nil, nil,
	)

	// Stop should not block indefinitely.
	done := make(chan struct{})
	go func() {
		stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not complete before timeout")
	}
}

// ---------------------------------------------------------------
// HAI-700: offline-start seed from persisted bundle
// ---------------------------------------------------------------

// TestPolicyRefresherOfflineStartSeedsIdentityFromValidBundle verifies that
// when a valid bundle exists on disk and the control plane is unreachable at
// startup, the refresher seeds identity from the persisted state. whoami
// failing does not block the loop; the seeded identity is used for policy
// decisions (HAI-700).
func TestPolicyRefresherOfflineStartSeedsIdentityFromValidBundle(t *testing.T) {
	now := time.Now().UTC()
	dir := t.TempDir()

	// Activate a valid bundle on disk.
	bundleBytes := unsignedExampleBundle(t, now)
	store, err := policybundle.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Activate(bundleBytes, "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", now)
	if err != nil {
		t.Fatal(err)
	}

	var seedIdentity *keiruntime.Identity
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ticks := make(chan time.Time)
	waits := make(chan time.Duration, 8)

	r := keiruntime.NewPolicyRefresher(
		policyTestConfig("http://cp-unreachable.example", dir),
		func() (*keiruntime.Identity, error) {
			return nil, errors.New("whoami: control plane unreachable")
		},
		func(*keiruntime.Identity) error { return nil }, // sync no-op
		nil, func() {},
	)
	r.Jitter = func(d time.Duration) time.Duration { return d }
	r.After = func(d time.Duration) <-chan time.Time { waits <- d; return ticks }
	r.OnIdentity = func(id *keiruntime.Identity) { seedIdentity = id }

	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	// Wait for the loop to compute its first poll interval (→ seed has fired).
	<-waits

	// Verify identity was seeded from the bundle's audience.
	if seedIdentity == nil {
		t.Fatal("OnIdentity was not called; expected seed from persisted bundle")
	}
	if seedIdentity.ID != "inst-fixture-0001" {
		t.Fatalf("seeded identity ID = %q, want %q", seedIdentity.ID, "inst-fixture-0001")
	}
	if seedIdentity.OrgID != "org-fixture-0001" {
		t.Fatalf("seeded identity OrgID = %q, want %q", seedIdentity.OrgID, "org-fixture-0001")
	}
	if seedIdentity.WorkspaceID == nil || *seedIdentity.WorkspaceID != "ws-fixture-0001" {
		t.Fatalf("seeded identity WorkspaceID = %v, want %q", seedIdentity.WorkspaceID, "ws-fixture-0001")
	}
	// AgentID is not persisted; must be empty.
	if seedIdentity.AgentID != "" {
		t.Fatalf("seeded identity AgentID = %q, want empty", seedIdentity.AgentID)
	}

	// Verify the store still holds a valid bundle.
	st, err := policybundle.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	status, err := st.Status(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if status.State != policybundle.Active && status.State != policybundle.Stale {
		t.Fatalf("bundle state = %s, want Active or Stale", status.State)
	}

	cancel()
	<-done
}

// TestPolicyRefresherOfflineStartExpiredBundleSeedsIdentity verifies that even
// when the persisted bundle has expired, the refresher seeds identity from the
// store. The evaluator constructed from an expired store will deny with
// policy_bundle_expired, which is the correct fail-closed behaviour (HAI-700).
func TestPolicyRefresherOfflineStartExpiredBundleSeedsIdentity(t *testing.T) {
	// Activate a bundle 13 hours ago so it is already expired.
	past := time.Now().UTC().Add(-13 * time.Hour)
	dir := t.TempDir()

	bundleBytes := unsignedExampleBundle(t, past)
	store, err := policybundle.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Activate(bundleBytes, "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", past)
	if err != nil {
		t.Fatal(err)
	}

	var seedIdentity *keiruntime.Identity
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ticks := make(chan time.Time)
	waits := make(chan time.Duration, 8)

	r := keiruntime.NewPolicyRefresher(
		policyTestConfig("http://cp-unreachable.example", dir),
		func() (*keiruntime.Identity, error) {
			return nil, errors.New("whoami: control plane unreachable")
		},
		func(*keiruntime.Identity) error { return nil },
		nil, func() {},
	)
	r.Jitter = func(d time.Duration) time.Duration { return d }
	r.After = func(d time.Duration) <-chan time.Time { waits <- d; return ticks }
	r.OnIdentity = func(id *keiruntime.Identity) { seedIdentity = id }

	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	<-waits

	// Identity should still be seeded from the expired store.
	if seedIdentity == nil {
		t.Fatal("OnIdentity was not called; expected seed from expired bundle")
	}
	if seedIdentity.ID != "inst-fixture-0001" {
		t.Fatalf("seeded identity ID = %q, want %q", seedIdentity.ID, "inst-fixture-0001")
	}

	// Verify the bundle is now expired.
	st, err := policybundle.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	status, err := st.Status(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if status.State != policybundle.Expired {
		t.Fatalf("bundle state = %s, want %s", status.State, policybundle.Expired)
	}

	cancel()
	<-done
}

// TestPolicyRefresherOfflineStartInvalidBundleSeedsIdentity verifies that even
// when the persisted bundle is missing (tampered / corrupted), the refresher
// seeds identity from the state file's audience. The evaluator will deny with
// policy_bundle_invalid, which is the correct fail-closed behaviour (HAI-700).
func TestPolicyRefresherOfflineStartInvalidBundleSeedsIdentity(t *testing.T) {
	now := time.Now().UTC()
	dir := t.TempDir()

	// Activate a valid bundle, then delete the bundle payload file so that
	// the next OpenStore+reload sets the state to Invalid.
	bundleBytes := unsignedExampleBundle(t, now)
	store, err := policybundle.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Activate(bundleBytes, "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", now)
	if err != nil {
		t.Fatal(err)
	}

	// Remove bundle.json — the store's persistCipher prevents direct
	// tampering, so deletion is the cleanest way to force Invalid state.
	bundlePath := filepath.Join(dir, "policy", "bundle.json")
	if err := os.Remove(bundlePath); err != nil {
		t.Fatal(err)
	}

	var seedIdentity *keiruntime.Identity
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ticks := make(chan time.Time)
	waits := make(chan time.Duration, 8)

	r := keiruntime.NewPolicyRefresher(
		policyTestConfig("http://cp-unreachable.example", dir),
		func() (*keiruntime.Identity, error) {
			return nil, errors.New("whoami: control plane unreachable")
		},
		func(*keiruntime.Identity) error { return nil },
		nil, func() {},
	)
	r.Jitter = func(d time.Duration) time.Duration { return d }
	r.After = func(d time.Duration) <-chan time.Time { waits <- d; return ticks }
	r.OnIdentity = func(id *keiruntime.Identity) { seedIdentity = id }

	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	<-waits

	// Identity should still be seeded — the state file still has the
	// audience even though the bundle payload is gone.
	if seedIdentity == nil {
		t.Fatal("OnIdentity was not called; expected seed from store with missing bundle")
	}
	if seedIdentity.ID != "inst-fixture-0001" {
		t.Fatalf("seeded identity ID = %q, want %q", seedIdentity.ID, "inst-fixture-0001")
	}

	// Verify the store reports Invalid.
	st, err := policybundle.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	status, err := st.Status(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if status.State != policybundle.Invalid {
		t.Fatalf("bundle state = %s, want %s", status.State, policybundle.Invalid)
	}

	cancel()
	<-done
}

// TestPolicyRefresherOfflineStartWhoamiRefreshAfterSeed verifies that a
// successful whoami call after seeding from the store refreshes the identity.
// This ensures no regression in the normal refresh path (HAI-700).
func TestPolicyRefresherOfflineStartWhoamiRefreshAfterSeed(t *testing.T) {
	now := time.Now().UTC()
	dir := t.TempDir()

	// Activate a valid bundle on disk.
	bundleBytes := unsignedExampleBundle(t, now)
	store, err := policybundle.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Activate(bundleBytes, "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", now)
	if err != nil {
		t.Fatal(err)
	}

	var identities []*keiruntime.Identity
	whoamiCalls := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ticks := make(chan time.Time)
	waits := make(chan time.Duration, 8)

	r := keiruntime.NewPolicyRefresher(
		policyTestConfig("http://cp-unreachable.example", dir),
		func() (*keiruntime.Identity, error) {
			whoamiCalls++
			// First whoami call fails; subsequent calls succeed.
			if whoamiCalls == 1 {
				return nil, errors.New("whoami: first attempt fails")
			}
			return &keiruntime.Identity{
				ID:          "refreshed-id-001",
				OrgID:       "refreshed-org-001",
				WorkspaceID: strPtr("refreshed-ws-001"),
				AgentID:     "agent-001",
			}, nil
		},
		func(*keiruntime.Identity) error { return nil },
		nil, func() {},
	)
	r.Jitter = func(d time.Duration) time.Duration { return d }
	r.After = func(d time.Duration) <-chan time.Time { waits <- d; return ticks }
	r.OnIdentity = func(id *keiruntime.Identity) { identities = append(identities, id) }

	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	// Wait for the loop to be ready for its first tick.
	<-waits

	// Advance one loop iteration: whoami fails (call 1), sync runs with
	// the seeded identity, then the loop waits for the next tick.
	ticks <- time.Now()
	<-waits // the loop is back waiting for another tick

	// Advance a second iteration: whoami succeeds (call 2), refreshes
	// identity, OnIdentity fires with the refreshed identity.
	ticks <- time.Now()
	<-waits

	cancel()
	<-done

	// identities[0] is the seed from the store.
	if len(identities) < 2 {
		t.Fatalf("OnIdentity was called %d times, want at least 2 (seed + refresh)", len(identities))
	}

	seed := identities[0]
	if seed.ID != "inst-fixture-0001" {
		t.Fatalf("seed identity ID = %q, want %q", seed.ID, "inst-fixture-0001")
	}

	// identities[1] should be the refreshed identity.
	refresh := identities[1]
	if refresh.ID != "refreshed-id-001" {
		t.Fatalf("refreshed identity ID = %q, want %q", refresh.ID, "refreshed-id-001")
	}
	if refresh.AgentID != "agent-001" {
		t.Fatalf("refreshed identity AgentID = %q, want %q", refresh.AgentID, "agent-001")
	}
}

// fakePolicyConfig is a PolicyConfig that satisfies the interface for testing.
type fakePolicyConfig struct {
	isRuntime    bool
	policyState  string
	token        string
	controlPlane string
}

func (f fakePolicyConfig) PolicyStateDir() string     { return f.policyState }
func (f fakePolicyConfig) Token() string              { return f.token }
func (f fakePolicyConfig) ControlPlaneURL() string    { return f.controlPlane }
func (f fakePolicyConfig) IsProduction() bool         { return false }
func (f fakePolicyConfig) Validate() error            { return nil }
func (f fakePolicyConfig) IsRuntime() bool            { return f.isRuntime }
func (f fakePolicyConfig) PolicyAuditPath() string    { return "" }
func (f fakePolicyConfig) PolicyAuditMaxBytes() int64 { return 0 }
