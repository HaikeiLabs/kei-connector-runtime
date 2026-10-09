// Package socket creates the runtime's local Unix domain socket listener.
package socket

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

// staleProbeTimeout bounds the dial used to tell a live socket from one left
// behind by a crashed process.
const staleProbeTimeout = 100 * time.Millisecond

// DefaultPath returns the default Unix socket path for goos.
//   - linux: /run/kei-proxy/runtime.sock
//   - darwin: $TMPDIR/kei-proxy/runtime.sock (falls back to os.TempDir())
//   - everything else: same as linux
//
// KEI_RUNTIME_SOCKET_PATH at the call site always overrides this value.
func DefaultPath(goos string) string {
	switch goos {
	case "darwin":
		return filepath.Join(os.TempDir(), "kei-proxy", "runtime.sock")
	default:
		return "/run/kei-proxy/runtime.sock"
	}
}

// DefaultPathOS is DefaultPath(runtime.GOOS).
func DefaultPathOS() string {
	return DefaultPath(runtime.GOOS)
}

// Listen creates an owner-only (0600) Unix socket at path, creating its parent
// directory (0700) if needed. It replaces a stale socket file left behind by a
// crash, but refuses to replace a socket that still accepts connections or any
// non-socket file. Closing the listener removes the socket file.
func Listen(path string) (net.Listener, error) {
	if path == "" {
		return nil, errors.New("socket path must not be empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create socket directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket at %s", path)
		}
		conn, dialErr := net.DialTimeout("unix", path, staleProbeTimeout)
		if dialErr == nil {
			_ = conn.Close()
			return nil, fmt.Errorf("socket is already in use at %s", path)
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) && !os.IsNotExist(dialErr) {
			return nil, fmt.Errorf("cannot determine whether existing socket is stale: %w", dialErr)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return listenPrivate(path)
}

// listenPrivate binds the socket in a private (0700) directory beside path,
// sets it to 0600, then renames it into place, so path never exists with the
// umask's wider mode, not even between bind and chmod.
func listenPrivate(path string) (net.Listener, error) {
	staging, err := os.MkdirTemp(filepath.Dir(path), ".kps")
	if err != nil {
		return nil, fmt.Errorf("create socket staging directory: %w", err)
	}
	defer os.RemoveAll(staging)
	tmp := filepath.Join(staging, "s")
	listener, err := net.Listen("unix", tmp)
	if err != nil {
		return nil, err
	}
	unixListener := listener.(*net.UnixListener)
	// The listener would unlink tmp on close; closeListener removes path.
	unixListener.SetUnlinkOnClose(false)
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("set socket permissions: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("move socket into place: %w", err)
	}
	return &closeListener{UnixListener: unixListener, path: path}, nil
}

// closeListener removes the socket file at path when it is closed.
type closeListener struct {
	*net.UnixListener
	path string
}

func (l *closeListener) Close() error {
	err := l.UnixListener.Close()
	if removeErr := os.Remove(l.path); removeErr != nil && !os.IsNotExist(removeErr) && err == nil {
		err = removeErr
	}
	return err
}
