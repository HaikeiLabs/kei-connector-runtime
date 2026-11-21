package connectorruntime

import (
	"os"
	"path/filepath"
	"testing"
)

// TestStatusHelpAndVersionDoNotCreateSocket guards the root dispatch wiring:
// the status, help, and version paths must never create the daemon socket.
func TestStatusHelpAndVersionDoNotCreateSocket(t *testing.T) {
	path := filepath.Join(shortSocketTempDir(t), "must-not-be-created.sock")
	t.Setenv("KEI_RUNTIME_SOCKET_PATH", path)

	if code := Main("test-version", []string{"--version"}); code != 0 {
		t.Fatalf("--version exit = %d", code)
	}
	if code := Main("test-version", []string{"--help"}); code != 0 {
		t.Fatalf("--help exit = %d", code)
	}
	if code := Main("test-version", []string{"status"}); code == 0 {
		t.Fatal("status for absent daemon unexpectedly succeeded")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("status/help/version created socket or returned unexpected stat error: %v", err)
	}
}
