package main

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// The release ldflags inject -X main.version into this package; the version
// command must report it so a released kei-proxy identifies its build.
func TestBuildVersionReachesVersionCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the kei-proxy binary")
	}
	binary := filepath.Join(t.TempDir(), "kei-proxy")
	build := exec.Command("go", "build", "-ldflags", "-X main.version=test-v9.8.7", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	out, err := exec.Command(binary, "version").Output()
	if err != nil {
		t.Fatalf("kei-proxy version: %v", err)
	}
	if got, want := string(out), "kei-proxy test-v9.8.7\n"; got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
}
