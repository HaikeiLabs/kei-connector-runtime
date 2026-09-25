// Command kei-proxy is the tenant-side runtime entrypoint. The binary name is
// an external contract (ADR-017): kei-chat-harness resolves it through
// KEI_PROXY_PATH, kei-cli through exec.LookPath("kei-proxy"), and releases are
// published under the kei-proxy/ S3 prefix.
package main

import (
	"log/slog"
	"os"

	connectorruntime "github.com/HaikeiLabs/kei-connector-runtime"
)

// These values are set at build time by the release configuration with
// -ldflags "-X main.version=... -X main.commit=... -X main.date=...".
var version = "dev"
var commit = "unknown"
var date = "unknown"

func main() {
	// Diagnostics are structured JSON on stderr (KEI-108): stdout is the
	// machine-readable protocol channel for the harness.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))

	os.Exit(connectorruntime.Main(version, os.Args[1:]))
}
