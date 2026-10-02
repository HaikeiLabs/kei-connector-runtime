package connectorruntime

import (
	"os/exec"
	"strings"
	"testing"
)

func TestStaticGuardNoViolations(t *testing.T) {
	cmd := exec.Command("git", "grep", "-lE",
		`(POST|PUT|PATCH|DELETE).*(policies|groups)|["']permit["']`,
		"--", "*.go", ":(exclude)*_test.go", ":(exclude)pkg/harness/*")
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
