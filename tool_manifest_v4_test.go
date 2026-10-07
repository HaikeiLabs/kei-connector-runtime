package connectorruntime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func v4ManifestJSON() []byte {
	return []byte(`{"schema":"kei.tool-manifest/v4","tools":[{"name":"github.get_issue","service":"github","source":"github","operation_class":"read","route":{"connector_binding":{"agent_id":"agent-1","connector_id":"connector-1"}},"required_capabilities":["issue.read"],"resource_types":[{"type":"issue","parent_type":"repository"}],"plan":{"args_schema":{"type":"object","properties":{"issue_number":{"type":"integer","minimum":1}},"required":["issue_number"],"additionalProperties":false},"context_schema":{"type":"object","properties":{"repository":{"type":"string","minLength":1,"maxLength":256,"pattern":"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"}},"required":["repository"],"additionalProperties":false},"operations":[{"id":"get-issue","capability":"issue.read","resource":{"type":"issue","id":{"from":"args","pointer":"/issue_number","type":"integer"},"parent":{"type":"repository","id":{"from":"context","field":"repository","type":"string"}}},"provider_resource_template":"repos/{parent.id}/issues/{resource.id}","provider_input":{}}]}}]}`)
}

func TestLoadToolManifestV4ValidatesPlanAndRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	valid := v4ManifestJSON()
	if err := os.WriteFile(path, valid, 0600); err != nil {
		t.Fatal(err)
	}
	manifest, err := LoadToolManifest(path)
	if err != nil {
		t.Fatalf("load valid v4 manifest: %v", err)
	}
	if manifest.Schema != ToolManifestSchemaV4 || len(manifest.Tools) != 1 || len(manifest.Tools[0].Plan) == 0 {
		t.Fatalf("loaded v4 manifest=%+v", manifest)
	}
	unknown := strings.Replace(string(valid), `"provider_input":{}`, `"provider_input":{},"unrecognized":true`, 1)
	if err := os.WriteFile(path, []byte(unknown), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadToolManifest(path); err == nil {
		t.Fatal("unknown v4 plan field accepted")
	}
	unknownSchema := strings.Replace(string(valid), `"maxLength":256`, `"maxLength":256,"patternFlag":true`, 1)
	if err := os.WriteFile(path, []byte(unknownSchema), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadToolManifest(path); err == nil {
		t.Fatal("unknown JSON Schema keyword accepted")
	}
}

func TestSyncToolManifestV4RequiresExplicitCatalogAcknowledgment(t *testing.T) {
	for _, tc := range []struct {
		name        string
		acknowledge bool
		wantErr     bool
	}{{"acknowledged", true, false}, {"missing acknowledgment", false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if got := r.Header.Get("Accept"); got != "application/json, application/vnd.kei.tool-manifest.v4+json" {
					t.Errorf("Accept=%q", got)
				}
				if r.Method != http.MethodPut || r.URL.Path != "/api/v1/runtime/tools" {
					t.Errorf("request %s %s", r.Method, r.URL.Path)
				}
				if tc.acknowledge {
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set(ToolManifestProtocolHeader, ToolManifestSchemaV4)
					w.Header().Set(ToolManifestSupportedHeader, ToolManifestSchemaV2+", "+ToolManifestSchemaV3+", "+ToolManifestSchemaV4)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			path := filepath.Join(t.TempDir(), "manifest.json")
			if err := os.WriteFile(path, v4ManifestJSON(), 0600); err != nil {
				t.Fatal(err)
			}
			cfg := Config{ToolManifestPath: path, RuntimeControlPlaneURL: server.URL, RuntimeToken: "test-token"}
			var stderr strings.Builder
			syncToolManifest(context.Background(), cfg, time.Second, func(url string, timeout time.Duration) RuntimeClient { return NewRuntimeClient(url, timeout) }, &stderr)
			if tc.wantErr {
				if requests != 1 || !strings.Contains(stderr.String(), "explicitly negotiated") {
					t.Fatalf("requests=%d stderr=%q", requests, stderr.String())
				}
			} else if requests != 1 || stderr.Len() != 0 {
				t.Fatalf("requests=%d stderr=%q", requests, stderr.String())
			}
		})
	}
}
