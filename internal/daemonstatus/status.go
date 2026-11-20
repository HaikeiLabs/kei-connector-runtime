// Package daemonstatus implements the local, read-only `status` probe for the
// kei-proxy daemon. It never loads runtime configuration, reads credentials,
// contacts a provider, or starts the daemon.
package daemonstatus

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/socket"
)

const statusProbeTimeout = 750 * time.Millisecond

var safeDaemonVersion = regexp.MustCompile(`^[A-Za-z0-9.+_-]{1,96}$`)

type daemonStatus struct {
	state   string
	version string
	reason  string
}

// Run probes the local daemon socket and writes a redacted status report to
// stdout. It returns 0 when the daemon is ready, 1 when it is not, and 2 on
// usage errors.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "status does not accept arguments")
		return 2
	}

	path := socketPathFromEnv()
	result := probeDaemonStatus(path)
	fmt.Fprintf(stdout, "status: %s\n", result.state)
	fmt.Fprintf(stdout, "socket: %s\n", displaySocketEndpoint(path))
	if result.version != "" {
		fmt.Fprintf(stdout, "version: %s\n", result.version)
	} else {
		fmt.Fprintln(stdout, "version: unavailable")
	}
	if result.reason != "" {
		fmt.Fprintf(stdout, "detail: %s\n", result.reason)
	}
	if result.state == "ready" {
		return 0
	}
	return 1
}

func socketPathFromEnv() string {
	if configured := os.Getenv("KEI_RUNTIME_SOCKET_PATH"); configured != "" {
		return configured
	}
	return socket.DefaultPathOS()
}

func displaySocketEndpoint(path string) string {
	if configured := os.Getenv("KEI_RUNTIME_SOCKET_PATH"); configured != "" {
		return "custom Unix socket (path redacted)"
	}
	if path == socket.DefaultPathOS() {
		if filepath.Clean(path) == filepath.Join(os.TempDir(), "kei-proxy", "runtime.sock") {
			if os.Getenv("TMPDIR") != "" {
				return "$TMPDIR/kei-proxy/runtime.sock"
			}
			return "system temp dir/kei-proxy/runtime.sock"
		}
		return path
	}
	return "Unix socket (path redacted)"
}

func probeDaemonStatus(path string) daemonStatus {
	if path == "" {
		return daemonStatus{state: "unavailable", reason: "socket path is not configured"}
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return daemonStatus{state: "unavailable", reason: "socket not found"}
	}
	if err != nil {
		return daemonStatus{state: "unavailable", reason: "socket cannot be inspected"}
	}
	if info.Mode()&os.ModeSocket == 0 {
		return daemonStatus{state: "unavailable", reason: "endpoint is not a Unix socket"}
	}
	if info.Mode().Perm() != 0o600 {
		return daemonStatus{state: "unavailable", reason: "socket permissions are not owner-only"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), statusProbeTimeout)
	defer cancel()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: statusProbeTimeout}).DialContext(ctx, "unix", path)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: statusProbeTimeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://kei-proxy/readyz", nil)
	if err != nil {
		return daemonStatus{state: "unavailable", reason: "readiness probe could not be created"}
	}
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return daemonStatus{state: "unavailable", reason: "stale socket"}
		}
		return daemonStatus{state: "unavailable", reason: "daemon is not reachable"}
	}
	defer resp.Body.Close()
	result := daemonStatus{state: "running (unready)", reason: "readiness probe did not succeed"}
	if version := resp.Header.Get("X-Kei-Proxy-Version"); safeDaemonVersion.MatchString(version) {
		result.version = version
	}
	if resp.StatusCode == http.StatusOK {
		result.state = "ready"
		result.reason = ""
	} else {
		result.reason = fmt.Sprintf("readiness endpoint returned HTTP %d", resp.StatusCode)
	}
	return result
}
