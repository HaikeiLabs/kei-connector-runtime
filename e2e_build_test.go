package connectorruntime

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// e2eAllowanceVariable is the only name the e2e-tagged private upstream
// allowance reads (internal/e2e, //go:build e2e). Its absence from a binary
// proves the allowance code was not compiled in.
const e2eAllowanceVariable = "KEI_PROXY_E2E_ALLOW_CIDRS"

// TestReleaseBinaryOmitsE2EAllowance builds kei-proxy the way .goreleaser.yaml
// does and checks the e2e allowance is physically absent; an e2e-tagged
// build of the same source proves the probe can see it.
func TestReleaseBinaryOmitsE2EAllowance(t *testing.T) {
	if testing.Short() {
		t.Skip("builds kei-proxy")
	}
	dir := t.TempDir()
	release := buildKeiProxy(t, filepath.Join(dir, "release"), "netgo")
	if bytes.Contains(release, []byte(e2eAllowanceVariable)) {
		t.Fatalf("a release build contains %s: the e2e allowance was compiled in", e2eAllowanceVariable)
	}
}

func buildKeiProxy(t *testing.T, out, tags string) []byte {
	t.Helper()
	cmd := exec.Command("go", "build", "-trimpath", "-tags", tags, "-o", out, "./cmd/kei-proxy")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build -tags %s: %v\n%s", tags, err, output)
	}
	binary, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read %s: %v", out, err)
	}
	return binary
}

// TestReleaseBuildsNeverUseE2ETag: no release build path (GoReleaser, the
// image, the release workflow) passes the e2e build tag.
func TestReleaseBuildsNeverUseE2ETag(t *testing.T) {
	tagArgument := regexp.MustCompile(`-tags[ =]["']?[^\s"']*\be2e\b`)
	for _, path := range []string{".goreleaser.yaml", "Dockerfile", filepath.Join(".github", "workflows", "release.yaml")} {
		content := readReleaseFile(t, path)
		if tagArgument.MatchString(content) {
			t.Errorf("%s passes -tags e2e", path)
		}
	}
	config := readReleaseFile(t, ".goreleaser.yaml")
	_, tags, ok := strings.Cut(config, "\n    tags:\n")
	if !ok {
		t.Fatal(".goreleaser.yaml has no build tags list")
	}
	for _, line := range strings.Split(tags, "\n") {
		item, isItem := strings.CutPrefix(line, "      - ")
		if !isItem {
			break
		}
		if strings.TrimSpace(item) == "e2e" {
			t.Error(".goreleaser.yaml build tags include e2e")
		}
	}
	// The release job checks the binaries it built, after GoReleaser.
	workflow := readReleaseFile(t, filepath.Join(".github", "workflows", "release.yaml"))
	_, afterRelease, _ := strings.Cut(workflow, "goreleaser/goreleaser-action@v6")
	for _, want := range []string{"Verify release binaries exclude the e2e build", "go version -m"} {
		if !strings.Contains(afterRelease, want) {
			t.Errorf("release workflow lacks the e2e artifact check (%q after GoReleaser)", want)
		}
	}
}
