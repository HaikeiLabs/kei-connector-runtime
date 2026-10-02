package harness

import (
	"strings"
	"testing"
	"time"
)

func TestCodexRenderingKeepsUnmatchedAtAskAndNeverAllowsAllShell(t *testing.T) {
	const policy = `{"policies":[{"id":"allow-status","src_pattern":"harness:codex","dst_pattern":"shell:git status","action":"permit","enabled":true},{"id":"bad-shell","src_pattern":"*","dst_pattern":"shell:*","action":"permit","enabled":true}]}`
	b := VerifiedBundle{ID: "bundle-1", Digest: "sha256:test", ExpiresAt: time.Now().Add(time.Hour), PolicyJSON: []byte(policy)}
	plan, err := (CodexAdapter{}).RenderPolicy(t.Context(), Env{HomeDir: "/home/example"}, b, Harness{ID: "h-1", Kind: Codex})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plan.Config), `decision="allow"`) {
		t.Fatalf("unexpected Codex rules: %s", plan.Config)
	}
	if len(ExpiredEntries(plan.Managed, time.Now().Add(2*time.Hour))) != 1 {
		t.Fatalf("expiry did not select the allow entry: %#v", plan.Managed)
	}
	foundAsk := false
	for _, entry := range plan.Managed {
		if strings.HasSuffix(entry.Path, ":approval_policy") && entry.Value == "on-request" {
			foundAsk = true
		}
	}
	if !foundAsk {
		t.Fatalf("Codex unmatched-command ask setting missing: %#v", plan.Managed)
	}
}

func TestOpenCodeRenderAddsManagedAskWithoutDroppingUserConfig(t *testing.T) {
	const policy = `{"policies":[{"id":"allow-status","src_pattern":"*","dst_pattern":"shell:git status","action":"permit","enabled":true}]}`
	out, err := Render("opencode", VerifiedBundle{PolicyJSON: []byte(policy)}, []byte(`{"model":"local/test","permission":{"bash":{"git log":"deny"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, want := range []string{`"model": "local/test"`, `"*": "ask"`, `"git status *": "allow"`, `"git log": "deny"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered config missing %s: %s", want, text)
		}
	}
}
