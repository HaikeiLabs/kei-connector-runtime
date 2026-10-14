package connectorruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("KEI_RUN_HELPER") == "1" {
		os.Exit(runHelperChild())
	}
	dir, err := os.MkdirTemp("", "kei-connector-runtime-test-state-")
	if err != nil {
		panic(err)
	}
	_ = os.Setenv("KEI_RUNTIME_STATE_DIR", filepath.Join(dir, "policy-state"))
	// Never run the real `kei harness sync` from a test (HAI-432).
	_ = os.Setenv("KEI_PROXY_HARNESS_RESYNC_INTERVAL", "off")
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// runHelperChild is the child `kei-proxy run` spawns in the commands:run
// tests (the test binary re-executed with KEI_RUN_HELPER=1). It reports the
// SHA-256 of $GH_TOKEN and its environment's keys, echoes the raw token on
// both streams (which the daemon must redact), and exits with
// $KEI_RUN_HELPER_EXIT.
func runHelperChild() int {
	token := os.Getenv("GH_TOKEN")
	sum := sha256.Sum256([]byte(token))
	var keys []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		keys = append(keys, key)
	}
	sort.Strings(keys)
	fmt.Printf("token-sha256=%s\n", hex.EncodeToString(sum[:]))
	fmt.Printf("raw=%s\n", token)
	fmt.Printf("env-keys=%s\n", strings.Join(keys, ","))
	fmt.Fprintf(os.Stderr, "err-raw=%s\n", token)
	// HAI-488: with an MCP route URL, ping the route with the injected key,
	// print the key (the daemon must redact it), and hand it to the test.
	if routeURL := os.Getenv("KEI_RUN_HELPER_MCP_URL"); routeURL != "" {
		key := os.Getenv("KEI_MCP_ROUTE_KEY")
		req, _ := http.NewRequest(http.MethodPost, routeURL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		req.Header.Set("Authorization", "Bearer "+key)
		status := 0
		if resp, err := http.DefaultClient.Do(req); err == nil {
			status = resp.StatusCode
			resp.Body.Close()
		}
		fmt.Printf("mcp-ping=%d\n", status)
		fmt.Printf("route-key=%s\n", key)
		if path := os.Getenv("KEI_RUN_HELPER_KEY_FILE"); path != "" {
			_ = os.WriteFile(path, []byte(key), 0o600)
		}
	}
	code, _ := strconv.Atoi(os.Getenv("KEI_RUN_HELPER_EXIT"))
	return code
}
