// Package statedir resolves the default runtime state directory per platform.
//
// The default varies by OS so that kei-proxy works out of the box on both
// Linux (server deployments) and macOS (developer workstations). An explicit
// KEI_RUNTIME_STATE_DIR at the call site always overrides the platform default.
//
// Resolution rules:
//   - darwin: $HOME/Library/Application Support/kei-proxy
//   - linux (and everything else), root: /var/lib/kei-proxy
//   - linux (and everything else), non-root, XDG_STATE_HOME set:
//     $XDG_STATE_HOME/kei-proxy
//   - linux (and everything else), non-root, XDG_STATE_HOME unset:
//     $HOME/.local/state/kei-proxy (the XDG default state home)
package statedir

import (
	"os"
	"path/filepath"
	"runtime"
)

// DefaultPath returns the default runtime state directory for goos with
// injectable OS-level inputs so callers can test platform logic without
// changing the real environment. An explicit KEI_RUNTIME_STATE_DIR at the
// call site always overrides this value.
func DefaultPath(goos, homeDir, xdgStateHome string, isRoot bool) string {
	switch goos {
	case "darwin":
		return filepath.Join(homeDir, "Library", "Application Support", "kei-proxy")
	default:
		if isRoot {
			return "/var/lib/kei-proxy"
		}
		if xdgStateHome != "" {
			return filepath.Join(xdgStateHome, "kei-proxy")
		}
		if homeDir == "" {
			return "/var/lib/kei-proxy"
		}
		return filepath.Join(homeDir, ".local", "state", "kei-proxy")
	}
}

// DefaultPathOS is DefaultPath for the runtime OS using real OS values.
// It is the production entry point.
func DefaultPathOS() string {
	homeDir, err := os.UserHomeDir()
	if err != nil || homeDir == "" {
		return "/var/lib/kei-proxy"
	}
	return DefaultPath(runtime.GOOS, homeDir, os.Getenv("XDG_STATE_HOME"), os.Geteuid() == 0)
}
