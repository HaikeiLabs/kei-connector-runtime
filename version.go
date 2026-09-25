package connectorruntime

import (
	"fmt"
	"io"
)

// version is the running release version. Main sets it from the build
// metadata injected into cmd/kei-proxy; "dev" covers tests and direct calls.
var version = "dev"

func printVersion(w io.Writer) {
	fmt.Fprintf(w, "kei-proxy %s\n", version)
}
