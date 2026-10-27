package harness

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestForKindReturnsCursorAdapter(t *testing.T) {
	adapter, err := ForKind("cursor")
	if err != nil {
		t.Fatal(err)
	}
	if adapter.Kind() != Cursor {
		t.Fatalf("Kind() = %q, want %q", adapter.Kind(), Cursor)
	}
}

func TestCursorDiscoveryGolden(t *testing.T) {
	got, err := (CursorAdapter{}).DiscoverTools(context.Background(), Env{HomeDir: filepath.Join("testdata", "cursor")})
	if err != nil {
		t.Fatal(err)
	}
	assertDiscoveryGolden(t, filepath.Join("testdata", "cursor", "discovery.golden.json"), got)
}

// TestCursorRenderMapsClosedPolicyToPermissionTokens pins the native-first
// mapping into cli-config.json permissions: single-token shell argv prefixes
// become Shell(base:*), harness tool policies become Read/Write/WebFetch, and
// MCP server.tool policies become Mcp(server:tool).
func TestCursorRenderMapsClosedPolicyToPermissionTokens(t *testing.T) {
	const policy = `{"policies":[
		{"id":"allow-git","src_pattern":"harness:cursor","dst_pattern":"shell:git","action":"permit","enabled":true},
		{"id":"deny-rm","src_pattern":"harness:cursor","dst_pattern":"shell:rm","action":"deny","enabled":true},
		{"id":"allow-linear","src_pattern":"harness:cursor","dst_pattern":"mcp:linear.create_issue","action":"permit","enabled":true},
		{"id":"allow-read","src_pattern":"harness:cursor","dst_pattern":"tool:cursor.read","action":"permit","enabled":true},
		{"id":"deny-write","src_pattern":"harness:cursor","dst_pattern":"tool:cursor.write","action":"deny","enabled":true},
		{"id":"allow-webfetch","src_pattern":"harness:cursor","dst_pattern":"tool:cursor.webfetch","action":"permit","enabled":true}
	]}`
	out, err := Render("cursor", VerifiedBundle{PolicyJSON: []byte(policy)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Permissions struct {
			Allow []string `json:"allow"`
			Deny  []string `json:"deny"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(doc.Permissions.Allow, []string{"Shell(git:*)", "Mcp(linear:create_issue)", "Read(**)", "WebFetch(*)"}) {
		t.Fatalf("allow = %v", doc.Permissions.Allow)
	}
	if !reflect.DeepEqual(doc.Permissions.Deny, []string{"Shell(rm:*)", "Write(**)"}) {
		t.Fatalf("deny = %v", doc.Permissions.Deny)
	}
}

// TestCursorRenderKeepsUserPermissionsAndBothArrays: user entries survive the
// merge and both arrays always exist, because Cursor requires them.
func TestCursorRenderKeepsUserPermissionsAndBothArrays(t *testing.T) {
	const policy = `{"policies":[{"id":"allow-git","src_pattern":"*","dst_pattern":"shell:git","action":"permit","enabled":true}]}`
	out, err := Render("cursor", VerifiedBundle{PolicyJSON: []byte(policy)}, []byte(`{"model":"composer-1","permissions":{"allow":["Read(docs/**)"],"deny":["Shell(rm:*)"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, want := range []string{`"model": "composer-1"`, `"Read(docs/**)"`, `"Shell(git:*)"`, `"Shell(rm:*)"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered config missing %s: %s", want, text)
		}
	}
	var doc struct {
		Permissions struct {
			Allow []string `json:"allow"`
			Deny  []string `json:"deny"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Permissions.Deny == nil {
		t.Fatal("permissions.deny missing after render")
	}
}

// TestCursorRenderPolicyTargetsCursorConfigAndReportsUngateablePolicies: the
// plan writes ~/.cursor/cli-config.json, leaves policies Cursor cannot express
// (skill:, multi-token shell rules) out of the config, and reports them so
// kei connect can surface hook-only and ungateable policies.
func TestCursorRenderPolicyTargetsCursorConfigAndReportsUngateablePolicies(t *testing.T) {
	dir := t.TempDir()
	const policy = `{"policies":[
		{"id":"allow-git","src_pattern":"*","dst_pattern":"shell:git","action":"permit","enabled":true},
		{"id":"skill-notes","src_pattern":"*","dst_pattern":"skill:release-notes","action":"permit","enabled":true},
		{"id":"deny-args","src_pattern":"*","dst_pattern":"shell:git status","action":"deny","enabled":true}
	]}`
	plan, err := (CursorAdapter{}).RenderPolicy(context.Background(), Env{HomeDir: dir}, VerifiedBundle{ID: "b1", Digest: "sha256:b1", ExpiresAt: time.Now().Add(time.Hour), PolicyJSON: []byte(policy)}, Harness{ID: "h-1"})
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, ".cursor", "cli-config.json"); plan.ConfigPath != want {
		t.Fatalf("ConfigPath = %q, want %q", plan.ConfigPath, want)
	}
	if !strings.Contains(string(plan.Config), `"Shell(git:*)"`) {
		t.Fatalf("config missing managed allow: %s", plan.Config)
	}
	if strings.Contains(string(plan.Config), "release-notes") || strings.Contains(string(plan.Config), "git status") {
		t.Fatalf("ungateable policy rendered into config: %s", plan.Config)
	}
	found := 0
	for _, w := range plan.Warnings {
		if strings.Contains(w, "skill:release-notes") || strings.Contains(w, "shell:git status") {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("warnings = %v, want ungateable reports for the skill and argv policies", plan.Warnings)
	}
	var spec struct {
		Kind    string   `json:"kind"`
		Command []string `json:"command"`
	}
	if err := json.Unmarshal(plan.Hook, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.Kind != "cursor" || !reflect.DeepEqual(spec.Command, []string{"kei-proxy", "hook", "cursor", "--harness", "h-1"}) {
		t.Fatalf("hook spec = %+v", spec)
	}
}

// TestCursorApplyAndExpiryRoundTrip applies a rendered cursor plan and then
// withdraws the expired allow while keeping the deny and the user's entries.
func TestCursorApplyAndExpiryRoundTrip(t *testing.T) {
	dir := t.TempDir()
	const policy = `{"policies":[
		{"id":"allow-git","src_pattern":"*","dst_pattern":"shell:git","action":"permit","enabled":true},
		{"id":"deny-rm","src_pattern":"*","dst_pattern":"shell:rm","action":"deny","enabled":true}
	]}`
	bundle := VerifiedBundle{ID: "b1", Digest: "sha256:b1", ExpiresAt: time.Unix(10, 0), PolicyJSON: []byte(policy)}
	plan, err := (CursorAdapter{}).RenderPolicy(context.Background(), Env{HomeDir: dir}, bundle, Harness{ID: "h-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyPlan(plan, Harness{ID: "h-1", Kind: Cursor}, bundle, filepath.Join(dir, "ledger.json"), time.Unix(1, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	if err := ExpireLedger(filepath.Join(dir, "ledger.json"), time.Unix(11, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, ".cursor", "cli-config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Permissions struct {
			Allow []string `json:"allow"`
			Deny  []string `json:"deny"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Permissions.Allow) != 0 {
		t.Fatalf("expired allow kept: %v", doc.Permissions.Allow)
	}
	if !reflect.DeepEqual(doc.Permissions.Deny, []string{"Shell(rm:*)"}) {
		t.Fatalf("deny after expiry = %v", doc.Permissions.Deny)
	}
}

func TestCursorHookSpecUsesCursorSubcommand(t *testing.T) {
	spec, err := HookSpec("cursor", "h-1")
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Kind    string   `json:"kind"`
		Command []string `json:"command"`
	}
	if err := json.Unmarshal(spec, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Kind != "cursor" {
		t.Fatalf("kind = %q", decoded.Kind)
	}
	want := []string{"kei-proxy", "hook", "cursor", "--harness", "h-1"}
	if !reflect.DeepEqual(decoded.Command, want) {
		t.Fatalf("command = %v, want %v", decoded.Command, want)
	}
}
