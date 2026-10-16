//go:build e2e

// The e2e build installs the private upstream allowance into the mcp route
// guard (ADR-036 §10, HAI-488 test 19). Release builds never compile this
// file, so the allowance and its variable are absent from them.

package connectorruntime

import (
	"github.com/HaikeiLabs/kei-connector-runtime/internal/e2e"
)

func init() { e2e.Install() }
