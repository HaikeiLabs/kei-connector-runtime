package harnessresync

import (
	"os"
	"path/filepath"
)

// DesktopConfigPresent reports whether a desktop harness config directory
// exists under home (or xdgConfigHome for OpenCode): ~/.claude, ~/.codex or
// the OpenCode config directory, the same directories `kei harness sync`
// detects. It stats directories only and never reads a file in them. A
// server installation has none, so the resync loop stays idle there.
func DesktopConfigPresent(home, xdgConfigHome string) bool {
	if home == "" {
		return false
	}
	if xdgConfigHome == "" {
		xdgConfigHome = filepath.Join(home, ".config")
	}
	for _, dir := range []string{
		filepath.Join(home, ".claude"),
		filepath.Join(home, ".codex"),
		filepath.Join(home, ".config", "opencode"),
		filepath.Join(xdgConfigHome, "opencode"),
	} {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			return true
		}
	}
	return false
}
