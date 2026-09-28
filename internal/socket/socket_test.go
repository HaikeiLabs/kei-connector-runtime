package socket

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// shortTempDir returns a directory under /tmp: macOS limits socket paths to
// 104 bytes, which t.TempDir can exceed.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "h201-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestListenCreatesOwnerOnlySocketAndRemovesItOnClose(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "run", "runtime.sock")
	listener, err := Listen(path)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("path mode = %v, want socket", info.Mode())
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("socket permissions = %04o, want 0600", got)
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("created directory permissions = %04o, want 0700", got)
	}

	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("socket after Close: stat err = %v, want not-exist", err)
	}
}

func TestListenRejectsEmptyPath(t *testing.T) {
	if _, err := Listen(""); err == nil {
		t.Fatal("Listen accepted an empty path")
	}
}

func TestListenRefusesRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "occupied")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path); err == nil {
		t.Fatal("Listen unexpectedly replaced a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "keep" {
		t.Fatalf("occupied path content = %q, want original file", data)
	}
}

func TestListenRefusesActiveSocket(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "runtime.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if _, err := Listen(path); err == nil {
		t.Fatal("Listen unexpectedly replaced an active socket")
	}
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("existing socket stopped accepting connections: %v", err)
	}
	_ = conn.Close()
}

func TestListenReplacesStaleSocket(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "runtime.sock")
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	// A crashed runtime leaves its socket file behind with no listener.
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stale socket was not left behind: %v", err)
	}

	listener, err := Listen(path)
	if err != nil {
		t.Fatalf("Listen over stale socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("recovered socket permissions = %04o, want 0600", got)
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial recovered socket: %v", err)
	}
	_ = conn.Close()
}

func TestListenFailsWhenDirectoryIsNotWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	dir := shortTempDir(t)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if listener, err := Listen(filepath.Join(dir, "runtime.sock")); err == nil {
		_ = listener.Close()
		t.Fatal("Listen succeeded in a read-only directory")
	}
}
