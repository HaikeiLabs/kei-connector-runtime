package policybundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// bundleFor rewrites the fixture's version and audience so one test can play
// two installations against the same state directory.
func bundleFor(t *testing.T, version int64, inst, org, ws string) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(fixtureBundle(t), &m); err != nil {
		t.Fatal(err)
	}
	m["bundle_version"] = version
	m["audience"] = map[string]any{"installation_id": inst, "org_id": org, "workspace_id": ws}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func archivedDirs(t *testing.T, stateDir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(stateDir, "policy", "archive"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, filepath.Join(stateDir, "policy", "archive", e.Name()))
	}
	return out
}

func TestStoreNewInstallationLowerVersionArchivesOldStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	inst, org, ws := audience()
	if _, err := s.Activate(fixtureBundle(t), inst, org, ws, fixtureNow()); err != nil {
		t.Fatal(err)
	}
	if got := s.HighestVersionFor("inst-new-0002", org, ws); got != 0 {
		t.Fatalf("watermark leaked across installations: %d", got)
	}
	if got := s.HighestVersionFor(inst, org, ws); got != 42 {
		t.Fatalf("same-audience watermark=%d", got)
	}
	next := bundleFor(t, 3, "inst-new-0002", org, ws)
	v, err := s.Activate(next, "inst-new-0002", org, ws, fixtureNow().Add(time.Minute))
	if err != nil {
		t.Fatalf("new installation rejected: %v", err)
	}
	if v.Payload.BundleVersion != 3 || s.HighestVersionFor("inst-new-0002", org, ws) != 3 || s.State() != Active {
		t.Fatalf("version=%d watermark=%d state=%s", v.Payload.BundleVersion, s.HighestVersionFor("inst-new-0002", org, ws), s.State())
	}
	archives := archivedDirs(t, dir)
	if len(archives) != 1 || !strings.HasSuffix(archives[0], "-"+inst) {
		t.Fatalf("archives=%v", archives)
	}
	var old diskState
	if err := readSecureFile(filepath.Join(archives[0], "state.json"), &old); err != nil {
		t.Fatal(err)
	}
	if old.Version != 42 || old.Audience.InstallationID != inst {
		t.Fatalf("archived state=%+v", old)
	}
	oldBundle, err := readSecureBytes(filepath.Join(archives[0], "bundle.json"))
	if err != nil || string(oldBundle) != string(fixtureBundle(t)) {
		t.Fatalf("archived bundle err=%v", err)
	}
	if _, state, err := s.Check("inst-new-0002", org, ws, fixtureNow().Add(2*time.Minute)); err != nil || state != Active {
		t.Fatalf("new installation check state=%s err=%v", state, err)
	}
}

func TestStoreNewWorkspaceOrOrgIsNewAudience(t *testing.T) {
	inst, org, ws := audience()
	for name, aud := range map[string][3]string{
		"workspace": {inst, org, "ws-other-0002"},
		"org":       {inst, "org-other-0002", ws},
	} {
		t.Run(name, func(t *testing.T) {
			s, err := OpenStore(filepath.Join(t.TempDir(), "state"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Activate(fixtureBundle(t), inst, org, ws, fixtureNow()); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Activate(bundleFor(t, 42, aud[0], aud[1], aud[2]), aud[0], aud[1], aud[2], fixtureNow()); err != nil {
				t.Fatalf("new audience rejected: %v", err)
			}
		})
	}
}

func TestStoreSameAudienceLowerOrEqualVersionStillRejected(t *testing.T) {
	inst, org, ws := audience()
	for name, version := range map[string]int64{"equal": 42, "lower": 41} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			s, err := OpenStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Activate(fixtureBundle(t), inst, org, ws, fixtureNow()); err != nil {
				t.Fatal(err)
			}
			_, err = s.Activate(bundleFor(t, version, inst, org, ws), inst, org, ws, fixtureNow().Add(time.Minute))
			if err == nil || !strings.Contains(err.Error(), "rollback or replay") {
				t.Fatalf("v%d accepted or wrong error: %v", version, err)
			}
			if s.HighestVersionFor(inst, org, ws) != 42 || s.State() != Active {
				t.Fatalf("watermark=%d state=%s", s.HighestVersionFor(inst, org, ws), s.State())
			}
			if a := archivedDirs(t, dir); len(a) != 0 {
				t.Fatalf("same audience archived: %v", a)
			}
		})
	}
}

func TestStoreInvalidNewInstallationCandidateKeepsOldStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	inst, org, ws := audience()
	if _, err := s.Activate(fixtureBundle(t), inst, org, ws, fixtureNow()); err != nil {
		t.Fatal(err)
	}
	// Payload audience names another installation than the caller expects.
	mismatched := bundleFor(t, 1, "inst-someone-else", org, ws)
	if _, err := s.Activate(mismatched, "inst-new-0002", org, ws, fixtureNow()); err == nil {
		t.Fatal("accepted audience-mismatched candidate")
	}
	if a := archivedDirs(t, dir); len(a) != 0 {
		t.Fatalf("rejected candidate archived old store: %v", a)
	}
	if s.HighestVersionFor(inst, org, ws) != 42 {
		t.Fatal("rejected candidate displaced previous installation state")
	}
}
