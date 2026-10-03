package ci

import (
	"os/exec"
	"strings"
	"testing"
)

func TestStaticGuardNoViolations(t *testing.T) {
	rootOut, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("git rev-parse --show-toplevel failed: %v", err)
	}
	cmd := exec.Command("git", "grep", "-lE",
		`(POST|PUT|PATCH|DELETE).*(policies|groups)|["']permit["']`,
		"--", "*.go", ":(exclude)*_test.go")
	cmd.Dir = strings.TrimSpace(string(rootOut))
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return
		}
		t.Fatalf("git grep failed: %v", err)
	}
	if matches := strings.TrimSpace(string(out)); matches != "" {
		t.Errorf("ADR-026 B1 violations found (policy/group write routes or default permit):\n%s", matches)
	}
}
