package invoke

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

// HAI-431: kei-proxy executes the skills_repo connector (skills.list and
// skills.fetch) through the kei-connector-contracts client and its GitHub
// backend. The runtime only wires the provider; these tests drive it through
// `kei-proxy connector invoke` against a fake GitHub API.

const (
	execSkillsTok = "fake-skills-repo-github-token-0001"
	skillsCaps    = `[{"name":"skills.list","action":"read"},{"name":"skills.fetch","action":"read"}]`
	skillsConfig  = `,"config":{"repo_url":"https://github.com/acme/skills","ref":"main","subdirectory":"skills/"}`
)

func demoSkills() map[string]map[string][]byte {
	return map[string]map[string][]byte{
		"demo": {"SKILL.md": skillMD("demo"), "scripts/run.sh": []byte("#!/bin/sh\necho deploy\n")},
		"lint": {"SKILL.md": skillMD("lint")},
	}
}

// skillsPerUserAllow is a catalog allow for a per_user OAuth skills_repo
// connector; the token is the invoking user's GitHub OAuth token.
func (h *execHarness) skillsPerUserAllow(capability, resource string) {
	h.catalogBody = allowJSON(envelopeJSON(capability, "read", resource, execUser),
		descriptorJSON("skills_repo", "oauth", "per_user", "", skillsCaps, skillsConfig), oauthJSON(h.now.Add(time.Minute)))
}

// skillsSharedAllow is a catalog allow for an opaque_ref skills_repo
// connector whose token is in the tenant secret store.
func (h *execHarness) skillsSharedAllow(capability, resource string) {
	h.store.values[execBackend+"|"+execSecretRef] = execSkillsTok
	h.catalogBody = allowJSON(envelopeJSON(capability, "read", resource, execUser),
		descriptorJSON("skills_repo", "opaque_ref", "", "", skillsCaps, skillsConfig), "")
}

func (h *execHarness) routeSkills(token string, skills map[string]map[string][]byte) *fakeSkillsGitHub {
	fake := newFakeSkillsGitHub(h.t, token, skills)
	h.transport.routes["api.github.com"] = fake.ServeHTTP
	return fake
}

func runSkills(h *execHarness, capability, resource string) (map[string]any, int) {
	h.t.Helper()
	out, code := h.run("--capability", capability, "--action", "read", "--resource", resource, "--user", execUser)
	for name, text := range map[string]string{"stdout": h.lastStdout, "stderr": h.lastStderr, "audit": strings.Join(h.lastAuditLines, "\n")} {
		if strings.Contains(text, execSkillsTok) {
			h.t.Fatalf("%s leaked the skills repository token", name)
		}
	}
	return out, code
}

func TestConnectorInvokeSkillsRepoListPerUser(t *testing.T) {
	h := newExecHarness(t)
	h.skillsPerUserAllow("skills.list", "skills")
	fake := h.routeSkills(execToken, demoSkills())
	out, code := runSkills(h, "skills.list", "skills")
	if code != 0 {
		t.Fatalf("outcome = %d %v (stderr %q)", code, out, h.lastStderr)
	}
	var listing struct {
		Ref    string `json:"ref"`
		Commit string `json:"commit"`
		Skills []struct {
			Name, Version, Description, Path string
			Harnesses                        []string
		} `json:"skills"`
	}
	raw, _ := json.Marshal(out["result"])
	if err := json.Unmarshal(raw, &listing); err != nil {
		t.Fatal(err)
	}
	if listing.Ref != "main" || listing.Commit != fake.commit || len(listing.Skills) != 2 {
		t.Fatalf("listing = %s", raw)
	}
	demo := listing.Skills[0]
	if demo.Name != "demo" || demo.Version != "1.2.0" || demo.Path != "skills/demo" || strings.Join(demo.Harnesses, ",") != "claude_code,codex" {
		t.Fatalf("demo = %+v", demo)
	}
	if rec := h.auditRecord(); rec["decision"] != "allow" || rec["credential_source"] != "oauth" || rec["result_digest"] == nil {
		t.Fatalf("audit = %v", rec)
	}
}

func TestConnectorInvokeSkillsRepoFetchCarriesItsDigest(t *testing.T) {
	h := newExecHarness(t)
	h.skillsSharedAllow("skills.fetch", "skills/demo")
	fake := h.routeSkills(execSkillsTok, demoSkills())
	out, code := runSkills(h, "skills.fetch", "skills/demo")
	if code != 0 {
		t.Fatalf("outcome = %d %v (stderr %q)", code, out, h.lastStderr)
	}
	archive := decodeSkillArchive(t, out["result"], fake.commit)
	files := untarSkill(t, archive)
	if string(files["demo/SKILL.md"]) != string(skillMD("demo")) || string(files["demo/scripts/run.sh"]) != "#!/bin/sh\necho deploy\n" || len(files) != 2 {
		t.Fatalf("archive files = %v", keys(files))
	}
	// Audit carries the result's digest and size, never the archive itself.
	rec := h.auditRecord()
	if rec["decision"] != "allow" || rec["credential_source"] != "opaque_ref" || rec["result_digest"] == nil {
		t.Fatalf("audit = %v", rec)
	}
	encoded := base64.StdEncoding.EncodeToString(archive)
	if strings.Contains(strings.Join(h.lastAuditLines, "\n"), encoded[:32]) || strings.Contains(h.lastStderr, encoded[:32]) {
		t.Fatal("the archive bytes reached audit or stderr")
	}
}

// A skill archive past the 1 MiB default result limit still returns: the
// connector declares the contract's archive bound for skills.fetch.
func TestConnectorInvokeSkillsRepoFetchAboveTheDefaultResultLimit(t *testing.T) {
	h := newExecHarness(t)
	h.skillsSharedAllow("skills.fetch", "skills/big")
	fake := h.routeSkills(execSkillsTok, map[string]map[string][]byte{
		"big": {"SKILL.md": skillMD("big"), "assets/blob.bin": randomBytes(t, 1536<<10)},
	})
	out, code := runSkills(h, "skills.fetch", "skills/big")
	if code != 0 {
		t.Fatalf("outcome = %d %v (stderr %q)", code, out, h.lastStderr)
	}
	if len(h.lastStdout) <= maxResultBytes {
		t.Fatalf("result is %d bytes; the case needs one past the default limit", len(h.lastStdout))
	}
	decodeSkillArchive(t, out["result"], fake.commit)
}

// An archive over the contract's archive bound fails closed with
// result_too_large and returns no bytes.
func TestConnectorInvokeSkillsRepoFetchOverTheArchiveBoundFailsClosed(t *testing.T) {
	h := newExecHarness(t)
	h.skillsSharedAllow("skills.fetch", "skills/huge")
	skill := map[string][]byte{"SKILL.md": skillMD("huge")}
	// Incompressible content totaling the contract's 8 MiB file bound: the
	// tar headers and gzip framing take the archive past it.
	remaining := 8<<20 - len(skill["SKILL.md"])
	for i := 0; remaining > 0; i++ {
		n := min(remaining, 2<<20)
		skill["assets/part"+string(rune('a'+i))+".bin"] = randomBytes(t, n)
		remaining -= n
	}
	fake := h.routeSkills(execSkillsTok, map[string]map[string][]byte{"huge": skill})
	out, code := runSkills(h, "skills.fetch", "skills/huge")
	h.assertDeny(out, code, "result_too_large")
	if fake.callCount() == 0 {
		t.Fatal("the bound must be enforced on the fetched archive")
	}
	if len(h.lastStdout) > 4<<10 {
		t.Fatalf("a denied fetch wrote %d bytes", len(h.lastStdout))
	}
}

// A catalog deny, and a resource that would leave the skills folder, make no
// GitHub call.
func TestConnectorInvokeSkillsRepoFailsClosedWithoutCallingGitHub(t *testing.T) {
	cases := []struct {
		name, capability, resource, reasonCode string
		setup                                  func(h *execHarness, capability, resource string)
	}{
		{"authorize deny", "skills.fetch", "skills/demo", "policy_deny", func(h *execHarness, _, _ string) {
			h.store.values[execBackend+"|"+execSecretRef] = execSkillsTok
			h.catalogBody = `{"decision":"deny","reason_code":"policy_deny","reason":"no matching policy"}`
		}},
		{"parent traversal", "skills.fetch", "skills/../secrets", "input_invalid", (*execHarness).skillsSharedAllow},
		{"nested traversal", "skills.fetch", "skills/demo/../../etc", "input_invalid", (*execHarness).skillsSharedAllow},
		{"dot name", "skills.fetch", "skills/.git", "input_invalid", (*execHarness).skillsSharedAllow},
		{"encoded traversal", "skills.fetch", "skills/%2e%2e", "input_invalid", (*execHarness).skillsSharedAllow},
		{"list with a name", "skills.list", "skills/demo", "input_invalid", (*execHarness).skillsSharedAllow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newExecHarness(t)
			tc.setup(h, tc.capability, tc.resource)
			fake := h.routeSkills(execSkillsTok, demoSkills())
			out, code := runSkills(h, tc.capability, tc.resource)
			h.assertDeny(out, code, tc.reasonCode)
			if n := fake.callCount(); n != 0 {
				t.Fatalf("github called %d times on a deny", n)
			}
		})
	}
}

// decodeSkillArchive checks a skills.fetch result's format, size, and digest
// against the archive bytes and returns them.
func decodeSkillArchive(t *testing.T, result any, commit string) []byte {
	t.Helper()
	var got struct {
		Skill   struct{ Name string } `json:"skill"`
		Commit  string                `json:"commit"`
		Format  string                `json:"format"`
		Digest  string                `json:"digest"`
		Size    int                   `json:"size"`
		Archive []byte                `json:"archive"`
	}
	raw, _ := json.Marshal(result)
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(got.Archive)
	if got.Format != "tar+gzip" || got.Commit != commit || got.Size != len(got.Archive) || got.Digest != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("archive: format %q commit %q size %d (len %d) digest %q", got.Format, got.Commit, got.Size, len(got.Archive), got.Digest)
	}
	return got.Archive
}

func untarSkill(t *testing.T, archive []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return files
		}
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		files[header.Name] = content
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
