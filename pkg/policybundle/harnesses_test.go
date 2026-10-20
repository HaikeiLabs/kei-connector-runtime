package policybundle

import (
	"testing"
	"time"
)

// v2BundleWithHarnesses builds a valid v2 bundle whose top-level harnesses[]
// lists the given registered harnesses.
func v2BundleWithHarnesses(t *testing.T, now time.Time, harnesses []map[string]any) []byte {
	t.Helper()
	doc := v2BundleDoc(now)
	if len(harnesses) > 0 {
		doc["harnesses"] = harnesses
		doc["harness_match_semantics"] = "kei.harness-match/v1"
	}
	return mustJSON(t, doc)
}

func TestHarnessesReturnsRegisteredFromV2Bundle(t *testing.T) {
	previous := schemaValidatorV2
	SetV2SchemaValidator(v2SchemaValidator(t))
	t.Cleanup(func() { SetV2SchemaValidator(previous) })
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	raw := v2BundleWithHarnesses(t, now, []map[string]any{
		{"agent_id": "agent-claude-001", "kind": "claude_code"},
		{"agent_id": "agent-codex-002", "kind": "codex"},
	})
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(raw, v2Installation, v2Org, v2Workspace, now); err != nil {
		t.Fatalf("activate v2 bundle: %v", err)
	}
	got, err := store.Harnesses(now)
	if err != nil {
		t.Fatalf("Harnesses: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("harnesses = %+v, want 2", got)
	}
	if got[0].AgentID != "agent-claude-001" || got[0].Kind != "claude_code" {
		t.Fatalf("harness[0] = %+v", got[0])
	}
	if got[1].AgentID != "agent-codex-002" || got[1].Kind != "codex" {
		t.Fatalf("harness[1] = %+v", got[1])
	}
}

func TestHarnessesEmptyWhenBundleMissing(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Harnesses(time.Now())
	if err != nil {
		t.Fatalf("Harnesses: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("harnesses = %+v, want empty for a cold store", got)
	}
}

func TestHarnessesEmptyWhenBundleExpired(t *testing.T) {
	previous := schemaValidatorV2
	SetV2SchemaValidator(v2SchemaValidator(t))
	t.Cleanup(func() { SetV2SchemaValidator(previous) })
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	raw := v2BundleWithHarnesses(t, now, []map[string]any{
		{"agent_id": "agent-claude-001", "kind": "claude_code"},
	})
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(raw, v2Installation, v2Org, v2Workspace, now); err != nil {
		t.Fatalf("activate v2 bundle: %v", err)
	}
	// not_after is now+12h. A check after that is expired even though the
	// persisted state is still active, so Harnesses must report empty.
	later := now.Add(13 * time.Hour)
	got, err := store.Harnesses(later)
	if err != nil {
		t.Fatalf("Harnesses: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("harnesses = %+v, want empty for an expired bundle", got)
	}
}
