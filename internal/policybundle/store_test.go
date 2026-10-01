package policybundle

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func init() { SetSchemaValidator(func([]byte) error { return nil }) }

func fixtureBundle(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../../docs/contracts/examples/policy-bundle-v1.payload.example.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func fixtureNow() time.Time { return time.Date(2026, 9, 28, 17, 0, 0, 0, time.UTC) }
func audience() (string, string, string) {
	return "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001"
}

func TestStoreSecurePersistenceReloadAndRevocation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "runtime-state")
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.State() != Cold {
		t.Fatalf("initial state=%s", s.State())
	}
	raw := fixtureBundle(t)
	inst, org, ws := audience()
	if _, err := s.Activate(raw, inst, org, ws, fixtureNow()); err != nil {
		t.Fatal(err)
	}
	if s.State() != Active {
		t.Fatalf("state=%s", s.State())
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("state dir mode=%o", info.Mode().Perm())
	}
	for _, name := range []string{"state.json", "bundle.json"} {
		info, err = os.Stat(filepath.Join(dir, "policy", name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode=%o", name, info.Mode().Perm())
		}
	}
	persisted, err := os.ReadFile(filepath.Join(dir, "policy", "bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(persisted, raw) {
		t.Fatal("persistence changed raw bundle bytes/digest")
	}
	reloaded, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	verified, state, err := reloaded.Check(inst, org, ws, fixtureNow().Add(time.Minute))
	if err != nil || verified == nil || state != Active || !bytes.Equal(verified.PayloadBytes, raw) {
		t.Fatalf("reload: verified=%v state=%s err=%v", verified != nil, state, err)
	}
	if err := reloaded.Revoke(fixtureNow()); err != nil {
		t.Fatal(err)
	}
	if _, state, err := reloaded.Check(inst, org, ws, fixtureNow()); err == nil || state != Revoked {
		t.Fatalf("revocation state=%s err=%v", state, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "policy", "bundle.json")); !os.IsNotExist(err) {
		t.Fatalf("revoked bundle persisted: %v", err)
	}
}

func TestStoreExpiryAndBadCandidatePreservesActiveBundle(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	raw := fixtureBundle(t)
	inst, org, ws := audience()
	if _, err := s.Activate(raw, inst, org, ws, fixtureNow()); err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), raw...)
	bad[len(bad)-2] ^= 1
	if _, err := s.Activate(bad, inst, org, ws, fixtureNow().Add(time.Minute)); err == nil {
		t.Fatal("accepted malformed candidate")
	}
	if s.State() != Active {
		t.Fatalf("rejected candidate displaced active state: %s", s.State())
	}
	if _, state, err := s.Check(inst, org, ws, time.Date(2026, 9, 29, 4, 0, 0, 0, time.UTC)); err == nil || state != Expired {
		t.Fatalf("expired bundle state=%s err=%v", state, err)
	}
}

func TestStoreRejectsModifiedPersistedBundleWithoutFallback(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	inst, org, ws := audience()
	if _, err := store.Activate(fixtureBundle(t), inst, org, ws, fixtureNow()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy", "bundle.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, ' ')
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	reloaded, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, state, err := reloaded.Check(inst, org, ws, fixtureNow()); err == nil || state != Invalid {
		t.Fatalf("modified state=%s err=%v", state, err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "policy"))
	if err != nil {
		t.Fatal(err)
	}
	bundles := 0
	for _, entry := range entries {
		if entry.Name() == "bundle.json" {
			bundles++
		}
	}
	if bundles != 1 {
		t.Fatalf("persisted bundle copies=%d; want exactly one and no fallback", bundles)
	}
}

func TestStoreRejectsSymlinkState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	pdir := filepath.Join(dir, "policy")
	if err := os.MkdirAll(pdir, 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(pdir, "state.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(dir); err == nil {
		t.Fatal("accepted symlink state file")
	}
}
