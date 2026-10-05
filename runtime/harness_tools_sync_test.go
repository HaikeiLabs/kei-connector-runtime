package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/harness"
)

type httpToolRegistryClient struct {
	baseURL string
	client  *http.Client
}

func (c httpToolRegistryClient) SyncTools(ctx context.Context, token string, manifest []byte) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/api/v1/runtime/tools", bytes.NewReader(manifest))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected tool registry response: %d", response.StatusCode)
	}
	return nil
}

func TestRunHarnessToolsSyncDiscoversAndPutsManifest(t *testing.T) {
	var got harness.ToolManifest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/v1/runtime/tools" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer kh_live_runtime_test_token_1234567890" {
			t.Errorf("unexpected authorization header")
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode manifest: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	var stderr bytes.Buffer
	client := httpToolRegistryClient{baseURL: server.URL, client: server.Client()}
	code := RunHarnessToolsSync(nil, &stderr, "kh_live_runtime_test_token_1234567890", client)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if got.Schema != "kei.tool-manifest/v3" || len(got.Tools) < 20 {
		t.Fatalf("manifest schema=%q tools=%d", got.Schema, len(got.Tools))
	}
	seen := make(map[string]bool)
	for _, tool := range got.Tools {
		seen[tool.Name] = true
		if tool.Name == "codex.shell" && (tool.Source != "codex" || tool.OperationClass != "write" || tool.Route.HarnessExecutor.Executor != "codex" || tool.Route.HarnessExecutor.Registration != "codex.shell") {
			t.Fatalf("unexpected harness route metadata: %+v", tool)
		}
	}
	for _, name := range []string{"claude_code.read", "codex.shell", "opencode.read"} {
		if !seen[name] {
			t.Errorf("full installation manifest missing %s", name)
		}
	}
	if !strings.Contains(stderr.String(), "registration grants no access") {
		t.Fatalf("expected metadata-only status, stderr=%s", stderr.String())
	}
}
