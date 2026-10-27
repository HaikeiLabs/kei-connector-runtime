package hooks

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

const registeredTestInput = `{"tool_name":"Bash","tool_input":{"command":"git status"},"native_decision":"ask"}`

// activateV2Bundle persists a valid v2 policy bundle in stateDir whose
// top-level harnesses[] lists the given registered harnesses, with not_after
// set to notAfter. The runtime is v2-only, so the registered-harness lookup is
// exercised against the v2 shape.
func activateV2Bundle(t *testing.T, stateDir string, harnesses []map[string]any, notAfter time.Time) {
	t.Helper()
	// The hooks package does not install the embedded schema validator (the
	// runtime binary does, in connectorruntime init). A no-op v2 validator is
	// enough here: ValidateV2 still runs every Go-level check (audience, dates,
	// validity window, policy set, harnesses).
	policybundle.SetV2SchemaValidator(func([]byte) error { return nil })
	now := time.Now().UTC()
	doc := map[string]any{
		"schema":             "kei.policy-bundle/v2",
		"bundle_id":          "bundle-test",
		"bundle_version":     1,
		"policy_revision":    1,
		"issuer":             "kei-policy-catalog",
		"audience":           map[string]any{"installation_id": "inst-test", "org_id": "org-test", "workspace_id": "ws-test"},
		"issued_at":          now.Add(-time.Hour).Format(time.RFC3339Nano),
		"not_after":          notAfter.Format(time.RFC3339Nano),
		"refresh":            map[string]any{"poll_interval_seconds": 60, "stale_after_seconds": 300},
		"subject_resolution": map[string]any{"mode": "bundle", "max_cache_seconds": 30},
		"policy_set": map[string]any{
			"schema":          "kei.policy-set/v2",
			"org_id":          "org-test",
			"workspace_id":    "ws-test",
			"match_semantics": "kei.match/v2",
			"evaluation": map[string]any{
				"precedence": []string{"priority_desc", "deny_before_permit", "policy_id_asc"},
				"checks":     "per_capability_first_match_and",
				"default":    "deny",
			},
			"tools":                   []any{},
			"checks":                  []any{},
			"tool_policies":           []any{},
			"harness_match_semantics": "kei.harness-match/v1",
			"harness_policies":        []any{},
		},
		"agent_connector_bindings": []any{},
		"identities":               []any{map[string]any{"source": "discord", "external_id": "ext-1", "user_id": "user-1", "status": "linked", "groups": []string{"members"}}},
	}
	if len(harnesses) > 0 {
		doc["harnesses"] = harnesses
		doc["harness_match_semantics"] = "kei.harness-match/v1"
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	store, err := policybundle.OpenStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(raw, "inst-test", "org-test", "ws-test", now); err != nil {
		t.Fatalf("activate v2 bundle: %v", err)
	}
}

// reportHarnessRegistered runs one hook report and returns the harness_registered
// field of the main (first) spooled event.
func reportHarnessRegistered(t *testing.T, cfg Config, args []string) bool {
	t.Helper()
	var spool []byte
	cfg.AppendAudit = func(record []byte) error {
		spool = append(spool, record...)
		spool = append(spool, '\n')
		return nil
	}
	var stdout, stderr bytes.Buffer
	if code := Run(args, strings.NewReader(registeredTestInput), &stdout, &stderr, cfg); code != 0 {
		t.Fatalf("Run(%v) exit = %d, stderr=%q", args, code, stderr.String())
	}
	line := strings.SplitN(strings.TrimSpace(string(spool)), "\n", 2)[0]
	var ev permissionEvent
	if err := json.Unmarshal([]byte(line), &ev); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	return ev.HarnessRegistered
}

func TestHarnessRegisteredMatch(t *testing.T) {
	stateDir := t.TempDir()
	activateV2Bundle(t, stateDir, []map[string]any{{"agent_id": "h1", "kind": "claude_code"}}, time.Now().Add(time.Hour))
	cfg := Config{RuntimeStateDir: stateDir}
	if !reportHarnessRegistered(t, cfg, []string{"claude", "--harness", "h1"}) {
		t.Fatal("harness_registered = false, want true for a registered match")
	}
}

func TestHarnessRegisteredKindMismatch(t *testing.T) {
	stateDir := t.TempDir()
	// The agent is registered, but under a different kind than the hook reports.
	activateV2Bundle(t, stateDir, []map[string]any{{"agent_id": "h1", "kind": "codex"}}, time.Now().Add(time.Hour))
	cfg := Config{RuntimeStateDir: stateDir}
	if reportHarnessRegistered(t, cfg, []string{"claude", "--harness", "h1"}) {
		t.Fatal("harness_registered = true, want false for a kind mismatch")
	}
}

func TestHarnessRegisteredAgentNotInBundle(t *testing.T) {
	stateDir := t.TempDir()
	activateV2Bundle(t, stateDir, []map[string]any{{"agent_id": "other", "kind": "claude_code"}}, time.Now().Add(time.Hour))
	cfg := Config{RuntimeStateDir: stateDir}
	if reportHarnessRegistered(t, cfg, []string{"claude", "--harness", "h1"}) {
		t.Fatal("harness_registered = true, want false when the agent is not in the bundle")
	}
}

func TestHarnessRegisteredBundleMissing(t *testing.T) {
	stateDir := t.TempDir()
	cfg := Config{RuntimeStateDir: stateDir}
	if reportHarnessRegistered(t, cfg, []string{"claude", "--harness", "h1"}) {
		t.Fatal("harness_registered = true, want false when the bundle is missing")
	}
}

func TestHarnessRegisteredBundleExpired(t *testing.T) {
	stateDir := t.TempDir()
	policyDir := filepath.Join(stateDir, "policy")
	if err := os.Mkdir(policyDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "bundle.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "state.json"), []byte(`{"state":"expired","highest_bundle_version":1,"bundle_digest":"sha256:test"}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{RuntimeStateDir: stateDir}
	if reportHarnessRegistered(t, cfg, []string{"claude", "--harness", "h1"}) {
		t.Fatal("harness_registered = true, want false when the bundle is expired")
	}
}

func TestHarnessRegisteredKindMapping(t *testing.T) {
	// The short→bundle kind mapping must resolve for every hook kind and reject
	// a mismatched kind.
	cases := []struct {
		kind   string
		bundle string
		want   bool
	}{
		{"claude", "claude_code", true},
		{"codex", "codex", true},
		{"opencode", "opencode", true},
		{"cursor", "cursor", true},
		{"claude", "codex", false},
		{"codex", "claude_code", false},
		{"opencode", "claude_code", false},
		{"cursor", "claude_code", false},
	}
	for _, tc := range cases {
		harnesses := []policybundle.Harness{{AgentID: "h1", Kind: tc.bundle}}
		if got := harnessRegistered(harnesses, "h1", tc.kind); got != tc.want {
			t.Errorf("harnessRegistered(kind=%s, bundle=%s) = %v, want %v", tc.kind, tc.bundle, got, tc.want)
		}
	}
	// An empty harness id never matches.
	if harnessRegistered(nil, "", "claude") {
		t.Error("harnessRegistered with an empty harness id must be false")
	}
}
