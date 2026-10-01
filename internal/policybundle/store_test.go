package policybundle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func init() { SetSchemaValidator(func([]byte) error { return nil }) }

func fixtureEnvelope(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../../docs/contracts/examples/policy-bundle-v1.envelope.example.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func fixtureKeys() KeySet {
	return KeySet{Keys: []Key{{KTY: "OKP", CRV: "Ed25519", X: "W5NclXraIJdyUtLqIHtaY7XfnhskAmqiub36Tgt_ye8", KID: "kei-pb-000000-01", Use: "sig", Alg: "EdDSA", Status: "active"}}}
}
func fixtureNow() time.Time { return time.Date(2026, 9, 28, 17, 0, 0, 0, time.UTC) }
func TestStoreSecurePersistenceReloadAndFailClosedRevocation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "runtime-state")
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.State() != Cold {
		t.Fatalf("initial state=%s", s.State())
	}
	if err := s.PinKeys(fixtureKeys()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Activate(fixtureEnvelope(t), "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", fixtureNow(), false); err != nil {
		t.Fatal(err)
	}
	if got := s.State(); got != Active {
		t.Fatalf("state=%s", got)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("state dir mode=%o", info.Mode().Perm())
	}
	info, err = os.Stat(filepath.Join(dir, "policy", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("state file mode=%o", info.Mode().Perm())
	}
	for _, name := range []string{"envelope.json", "keys.json"} {
		info, err = os.Stat(filepath.Join(dir, "policy", name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode=%o", name, info.Mode().Perm())
		}
	}
	reloaded, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	verified, state, err := reloaded.Check("inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", fixtureNow().Add(time.Minute), false)
	if err != nil || verified == nil || state != Active {
		t.Fatalf("reload check: verified=%v state=%s err=%v", verified != nil, state, err)
	}
	if err := reloaded.PinKeys(KeySet{Keys: fixtureKeys().Keys, RevokedKeyIDs: []string{"kei-pb-000000-01"}}); err != nil {
		t.Fatal(err)
	}
	if _, state, err := reloaded.Check("inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", fixtureNow(), false); err == nil || state != Invalid {
		t.Fatalf("revoked persisted bundle state=%s err=%v", state, err)
	}
	if err := reloaded.PinKeys(fixtureKeys()); err != nil {
		t.Fatal(err)
	}
	if len(reloaded.PinnedKeys().RevokedKeyIDs) != 1 {
		t.Fatal("key revocation was not sticky")
	}
}
func TestStoreExpiryAndBadCandidatePreservesActiveBundle(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PinKeys(fixtureKeys()); err != nil {
		t.Fatal(err)
	}
	env := fixtureEnvelope(t)
	if _, err := s.Activate(env, "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", fixtureNow(), false); err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), env...)
	bad[len(bad)-3] ^= 1
	if _, err := s.Activate(bad, "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", fixtureNow().Add(time.Minute), false); err == nil {
		t.Fatal("accepted invalid candidate")
	}
	if s.State() != Active {
		t.Fatalf("rejected candidate displaced active state: %s", s.State())
	}
	if _, state, err := s.Check("inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", time.Date(2026, 9, 29, 4, 0, 0, 0, time.UTC), false); err == nil || state != Expired {
		t.Fatalf("expired bundle state=%s err=%v", state, err)
	}
}
func TestStoreRejectsTamperedPersistedEnvelopeWithoutFallback(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PinKeys(fixtureKeys()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(fixtureEnvelope(t), "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", fixtureNow(), false); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy", "envelope.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-3] ^= 1
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	reloaded, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, state, err := reloaded.Check("inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", fixtureNow(), false); err == nil || state != Invalid {
		t.Fatalf("tampered state=%s err=%v", state, err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "policy"))
	if err != nil {
		t.Fatal(err)
	}
	envelopes := 0
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "envelope") {
			envelopes++
		}
	}
	if envelopes != 1 {
		t.Fatalf("persisted envelope copies=%d; want exactly one, no fallback copy", envelopes)
	}
}

func TestStoreRejectsSymlinkStateAndStickyRevocation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(filepath.Join(dir, "policy"), 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "policy", "state.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(dir); err == nil {
		t.Fatal("accepted symlink state file")
	}
}
