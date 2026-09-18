package main

import (
	"fmt"
	"io"
)

// These values are set at build time by the release configuration with
// -ldflags "-X main.version=... -X main.commit=... -X main.date=...".
var version = "dev"
var commit = "unknown"
var date = "unknown"

func printVersion(w io.Writer) {
	fmt.Fprintf(w, "kei-proxy %s\n", version)
}
