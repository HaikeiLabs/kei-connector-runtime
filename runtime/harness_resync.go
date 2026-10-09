package runtime

import (
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/harnessresync"
)

// HarnessResyncIntervalEnv sets the desktop harness drift-check timer as a Go
// duration (default 5m); "0" or "off" disables the resync loop.
const HarnessResyncIntervalEnv = "KEI_PROXY_HARNESS_RESYNC_INTERVAL"

// NewHarnessResync returns the desktop harness resync loop for the policy
// refresher (HAI-432), or nil when it is disabled, the interval is invalid,
// or no `kei` binary sits next to kei-proxy or on PATH. Whether a desktop
// harness config exists is checked on every cycle, so a server installation
// never runs `kei`.
func NewHarnessResync(cfg PolicyConfig, getenv func(string) string) *harnessresync.Resyncer {
	interval := harnessresync.DefaultInterval
	if raw := strings.TrimSpace(getenv(HarnessResyncIntervalEnv)); raw != "" {
		if raw == "off" || raw == "0" {
			return nil
		}
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			slog.Warn("harness resync disabled: invalid interval", "env", HarnessResyncIntervalEnv)
			return nil
		}
		interval = d
	}
	kei, err := harnessresync.ResolveKei(os.Executable, exec.LookPath)
	if err != nil {
		slog.Debug("harness resync disabled: kei binary not found")
		return nil
	}
	home, xdg := getenv("HOME"), getenv("XDG_CONFIG_HOME")
	return harnessresync.New(
		harnessresync.ExecRunner{Path: kei},
		func() bool { return harnessresync.DesktopConfigPresent(home, xdg) },
		interval,
		cfg.PolicyStateDir(),
	)
}
