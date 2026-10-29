package ci

import (
	"os/exec"
	"strings"
	"testing"
)

// B-34: a resource is passed through as the caller named it. Production code
// must not rewrite it into the GitHub-shaped "<service>:repo:<name>" form the
// removed v1 AuthorizeTool built.
func TestNoGitHubShapedResourceInProductionCode(t *testing.T) {
	rootOut, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("git rev-parse --show-toplevel failed: %v", err)
	}
	cmd := exec.Command("git", "grep", "-nF", `":repo:"`, "--", "*.go", ":(exclude)*_test.go")
	cmd.Dir = strings.TrimSpace(string(rootOut))
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return
		}
		t.Fatalf("git grep failed: %v", err)
	}
	if matches := strings.TrimSpace(string(out)); matches != "" {
		t.Errorf("GitHub-shaped resource prefix found in production code:\n%s", matches)
	}
}
