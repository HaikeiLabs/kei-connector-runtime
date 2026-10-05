package statedir

import (
	"os"
	"runtime"
	"testing"
)

func TestDefaultPath(t *testing.T) {
	tests := []struct {
		name         string
		goos         string
		homeDir      string
		xdgStateHome string
		isRoot       bool
		want         string
	}{
		{
			name:    "darwin default",
			goos:    "darwin",
			homeDir: "/Users/testuser",
			want:    "/Users/testuser/Library/Application Support/kei-proxy",
		},
		{
			name:    "linux default (no XDG_STATE_HOME, not root)",
			goos:    "linux",
			homeDir: "/root",
			want:    "/var/lib/kei-proxy",
		},
		{
			name:         "linux with XDG_STATE_HOME, not root",
			goos:         "linux",
			homeDir:      "/home/testuser",
			xdgStateHome: "/home/testuser/.local/state",
			want:         "/home/testuser/.local/state/kei-proxy",
		},
		{
			name:         "linux with XDG_STATE_HOME as root",
			goos:         "linux",
			homeDir:      "/root",
			xdgStateHome: "/root/.local/state",
			isRoot:       true,
			want:         "/var/lib/kei-proxy",
		},
		{
			name:         "linux with empty XDG_STATE_HOME, not root",
			goos:         "linux",
			homeDir:      "/home/testuser",
			xdgStateHome: "",
			want:         "/var/lib/kei-proxy",
		},
		{
			name:    "android falls to linux default",
			goos:    "android",
			homeDir: "/",
			want:    "/var/lib/kei-proxy",
		},
		{
			name:         "darwin ignores XDG_STATE_HOME and isRoot",
			goos:         "darwin",
			homeDir:      "/Users/developer",
			xdgStateHome: "/some/state",
			isRoot:       true,
			want:         "/Users/developer/Library/Application Support/kei-proxy",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DefaultPath(tt.goos, tt.homeDir, tt.xdgStateHome, tt.isRoot); got != tt.want {
				t.Fatalf("DefaultPath(%q, %q, %q, %v) = %q, want %q",
					tt.goos, tt.homeDir, tt.xdgStateHome, tt.isRoot, got, tt.want)
			}
		})
	}
}

func TestDefaultPathOS(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	if err != nil || homeDir == "" {
		t.Skip("no home directory available")
	}
	want := DefaultPath(runtime.GOOS, homeDir, os.Getenv("XDG_STATE_HOME"), os.Geteuid() == 0)
	if got := DefaultPathOS(); got != want {
		t.Fatalf("DefaultPathOS() = %q, want %q", got, want)
	}
}
