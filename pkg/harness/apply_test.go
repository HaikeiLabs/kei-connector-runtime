package harness

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestApplyPlanBacksUpAndExpiryRemovesOnlyManagedAllow(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "settings.json")
	ledger := filepath.Join(dir, "ledger.json")
	original := []byte(`{"permissions":{"allow":["Read"],"deny":[]}}`)
	if err := os.WriteFile(config, original, 0600); err != nil {
		t.Fatal(err)
	}
	updated := []byte(`{"permissions":{"allow":["Read","Edit"],"deny":["Bash(*)"]}}`)
	entries := []ManagedEntry{{Path: "permissions.allow", Value: "Edit", Decision: "permit", PolicyID: "p1", RemoveOnExpiry: true, ExpiresAt: time.Unix(10, 0)}, {Path: "permissions.deny", Value: "Bash(*)", Decision: "deny", PolicyID: "p2", ExpiresAt: time.Unix(10, 0)}}
	now := time.Unix(1, 0).UTC()
	plan := RenderPlan{ConfigPath: config, Config: updated, Managed: entries}
	if err := ApplyPlan(plan, Harness{ID: "h1", Kind: ClaudeCode}, VerifiedBundle{ID: "b1", Digest: "sha256:one", ExpiresAt: time.Unix(10, 0)}, ledger, now); err != nil {
		t.Fatal(err)
	}
	backups, err := filepath.Glob(config + ".kei-backup-*")
	if err != nil || len(backups) != 1 {
		t.Fatalf("backups=%v err=%v", backups, err)
	}
	if err := ExpireLedger(ledger, time.Unix(11, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = json.Unmarshal(got, &doc); err != nil {
		t.Fatal(err)
	}
	permissions := doc["permissions"].(map[string]any)
	allows := permissions["allow"].([]any)
	if len(allows) != 1 || allows[0] != "Read" || !strings.Contains(string(got), "Bash(*)") {
		t.Fatalf("expired config = %s", got)
	}
	stored, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	var saved SyncLedger
	if err = json.Unmarshal(stored, &saved); err != nil {
		t.Fatal(err)
	}
	if len(saved.Entries) != 1 || saved.Entries[0].Decision != "deny" {
		t.Fatalf("ledger after expiry = %#v", saved.Entries)
	}
}
