// Package runtime contains customer-runtime control-plane operations.
package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/harness"
)

// ToolRegistryClient sends a complete discovered tool manifest to the runtime
// registry. The byte payload keeps this package independent of the CLI root's
// client types while preserving the canonical v2 JSON body.
type ToolRegistryClient interface {
	SyncTools(ctx context.Context, token string, manifest []byte) error
}

// RunHarnessToolsSync discovers every supported harness kind and syncs their
// combined registry metadata. The registry endpoint replaces the complete tool
// set, so discovery is deliberately not narrowed to one harness kind.
func RunHarnessToolsSync(args []string, stderr io.Writer, token string, client ToolRegistryClient) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "harness tools sync accepts no arguments")
		return 2
	}
	kinds := []harness.Kind{harness.ClaudeCode, harness.Codex, harness.OpenCode}
	discoveries := make([]harness.Discovery, 0, len(kinds))
	for _, kind := range kinds {
		adapter, err := harness.ForKind(kind)
		if err != nil {
			fmt.Fprintf(stderr, "harness tools sync failed: %v\n", err)
			return 1
		}
		discovery, err := adapter.DiscoverTools(context.Background(), harness.Env{})
		if err != nil {
			fmt.Fprintln(stderr, "harness tools sync failed: discovery error")
			return 1
		}
		discoveries = append(discoveries, discovery)
	}
	metadata := harness.ManifestFromDiscovery(discoveries...)
	manifest, err := json.Marshal(metadata)
	if err != nil {
		fmt.Fprintln(stderr, "harness tools sync failed: could not encode manifest")
		return 1
	}
	if err := client.SyncTools(context.Background(), token, manifest); err != nil {
		fmt.Fprintf(stderr, "harness tools sync failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stderr, "synced %d discovered harness tools; registration grants no access\n", len(metadata.Tools))
	return 0
}
