package connectorruntime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSyncToolManifestUnsupportedSchemaSkips(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dir := t.TempDir()
	manifestPath := dir + "/manifest.json"
	if err := os.WriteFile(manifestPath, []byte(`{"schema":"kei.tool-manifest/v9","tools":[{"name":"test.tool","service":"test"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		RuntimeControlPlaneURL: server.URL,
		RuntimeToken:           "test-token",
		ToolManifestPath:       manifestPath,
	}
	var stderr strings.Builder
	syncToolManifest(context.Background(), cfg, time.Second, NewRuntimeClient, &stderr)
	if requests != 0 {
		t.Fatalf("control-plane requests = %d, want 0 (unsupported schema must skip the sync)", requests)
	}
	if !strings.Contains(stderr.String(), "unsupported manifest schema") {
		t.Fatalf("expected unsupported-schema skip on stderr, got %q", stderr.String())
	}
}

func TestLoadToolManifestV1SchemaRejected(t *testing.T) {
	path := t.TempDir() + "/v1.json"
	if err := os.WriteFile(path, []byte(`{"schema":"kei.tool-manifest/v1","tools":[{"name":"test.tool","service":"test","action":"read","resources":["r:*"]}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadToolManifest(path)
	if err == nil || !strings.Contains(err.Error(), "unsupported manifest schema") {
		t.Fatalf("expected v1 schema rejection, got %v", err)
	}
}

func TestLoadToolManifestSchemalessRejected(t *testing.T) {
	path := t.TempDir() + "/schemaless.json"
	if err := os.WriteFile(path, []byte(`{"tools":[{"name":"test.tool","service":"test"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadToolManifest(path)
	if err == nil || !strings.Contains(err.Error(), "unsupported manifest schema") {
		t.Fatalf("expected schema-less rejection, got %v", err)
	}
}

func TestLoadToolManifestV2HappyPath(t *testing.T) {
	m, err := LoadToolManifest("testdata/tool-manifest.v2.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Tools) != 3 {
		t.Fatalf("tools = %d, want 3", len(m.Tools))
	}
	if m.Schema != ToolManifestSchemaV2 {
		t.Fatalf("schema = %q, want %q", m.Schema, ToolManifestSchemaV2)
	}
	td := m.Tools[0]
	if td.Name != "github.get_issue" || td.Source != "github" {
		t.Fatalf("tool[0] = %+v", td)
	}
	if len(td.RequiredCapabilities) != 1 || td.RequiredCapabilities[0] != "issue.read" {
		t.Fatalf("tool[0] capabilities = %v", td.RequiredCapabilities)
	}
	if len(td.ResourceTypes) != 1 || td.ResourceTypes[0].Type != "issue" || td.ResourceTypes[0].ParentType != "repository" {
		t.Fatalf("tool[0] resource_types = %+v", td.ResourceTypes)
	}
	if td.OperationClass != "read" {
		t.Fatalf("tool[0] operation_class = %q", td.OperationClass)
	}
	if td.Service != "github" {
		t.Fatalf("tool[0] service = %q", td.Service)
	}
}

func TestSyncToolManifestV2PassesSchemaThrough(t *testing.T) {
	var gotSchema string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body ToolManifest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		gotSchema = body.Schema
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ToolSyncResponse{Added: 1})
	}))
	defer server.Close()

	client := NewRuntimeClient(server.URL, time.Second)
	manifest := &ToolManifest{Schema: ToolManifestSchemaV2, Tools: []ToolDefinition{
		{Name: "github.get_issue", Source: "github", RequiredCapabilities: []string{"issue.read"}, ResourceTypes: []KeiResourceType{{Type: "issue", ParentType: "repository"}}, OperationClass: "read", Service: "github"},
	}}
	if err := client.SyncTools(context.Background(), "test-token", manifest); err != nil {
		t.Fatal(err)
	}
	if gotSchema != ToolManifestSchemaV2 {
		t.Fatalf("PUT body schema = %q, want %q", gotSchema, ToolManifestSchemaV2)
	}
}

func TestLoadToolManifestMissingFile(t *testing.T) {
	_, err := LoadToolManifest("testdata/nonexistent.json")
	if err == nil || !strings.Contains(err.Error(), "read tool manifest") {
		t.Fatalf("expected file-not-found error, got %v", err)
	}
}

func TestLoadToolManifestInvalidJSON(t *testing.T) {
	path := t.TempDir() + "/bad.json"
	if err := os.WriteFile(path, []byte(`not json`), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadToolManifest(path)
	if err == nil || !strings.Contains(err.Error(), "decode tool manifest") {
		t.Fatalf("expected decode error, got %v", err)
	}
}

func TestLoadToolManifestEmptyToolsList(t *testing.T) {
	path := t.TempDir() + "/empty.json"
	if err := os.WriteFile(path, []byte(`{"schema":"kei.tool-manifest/v2","tools":[]}`), 0644); err != nil {
		t.Fatal(err)
	}
	m, err := LoadToolManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Tools) != 0 {
		t.Fatalf("tools = %d, want 0", len(m.Tools))
	}
}

func TestLoadToolManifestNullTools(t *testing.T) {
	path := t.TempDir() + "/null-tools.json"
	if err := os.WriteFile(path, []byte(`{"schema":"kei.tool-manifest/v2","tools":null}`), 0644); err != nil {
		t.Fatal(err)
	}
	m, err := LoadToolManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Tools) != 0 {
		t.Fatalf("tools = %d, want 0", len(m.Tools))
	}
}

func TestSyncToolsSendsPUTAndParsesResponse(t *testing.T) {
	routes := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/v1/runtime/tools" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("Authorization = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("Content-Type = %q", got)
		}
		if got := r.Header.Get("Accept"); got != "application/json, application/vnd.kei.tool-manifest.v2+json" {
			t.Fatalf("Accept = %q, want v2 media type", got)
		}
		var body ToolManifest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body.Tools) != 1 || body.Tools[0].Name != "test.tool" {
			t.Fatalf("unexpected body: %+v", body)
		}
		routes["PUT /api/v1/runtime/tools"]++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(ToolManifestProtocolHeader, ToolManifestSchemaV2)
		w.Header().Set(ToolManifestSupportedHeader, ToolManifestSchemaV2+", "+ToolManifestSchemaV3)
		json.NewEncoder(w).Encode(ToolSyncResponse{Added: 1, Unchanged: 1})
	}))
	defer server.Close()

	client := NewRuntimeClient(server.URL, time.Second)
	manifest := &ToolManifest{Schema: ToolManifestSchemaV2, Tools: []ToolDefinition{
		{Name: "test.tool", Source: "test", RequiredCapabilities: []string{"r"}, ResourceTypes: []KeiResourceType{{Type: "r"}}, OperationClass: "read"},
	}}
	if err := client.SyncTools(context.Background(), "test-token", manifest); err != nil {
		t.Fatal(err)
	}
	if routes["PUT /api/v1/runtime/tools"] != 1 {
		t.Fatalf("PUT calls = %d, want 1", routes["PUT /api/v1/runtime/tools"])
	}
}

func TestSyncToolsV3RequiresExplicitProtocolAcknowledgment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept"); got != "application/json, application/vnd.kei.tool-manifest.v3+json" {
			t.Fatalf("Accept = %q, want v3 media type", got)
		}
		w.WriteHeader(http.StatusOK) // legacy endpoint did not negotiate v3
	}))
	defer server.Close()
	client := NewRuntimeClient(server.URL, time.Second)
	manifest := &ToolManifest{Schema: ToolManifestSchemaV3, Tools: []ToolDefinition{{
		Name: "local.echo", Service: "harness", Source: "local", OperationClass: "write",
		Route: &ToolRoute{HarnessExecutor: &HarnessExecutorRoute{Executor: "harness", Registration: "echo"}},
	}}}
	if err := client.SyncTools(context.Background(), "test-token", manifest); err == nil || !strings.Contains(err.Error(), "not explicitly negotiated") {
		t.Fatalf("SyncTools error = %v, want missing-v3-ack failure", err)
	}
}

func TestSyncToolsPreservesLegacyV2PeerCompatibility(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept"); got != "application/json, application/vnd.kei.tool-manifest.v2+json" {
			t.Fatalf("Accept = %q", got)
		}
		w.WriteHeader(http.StatusOK) // pre-negotiation v2 catalog
	}))
	defer server.Close()
	client := NewRuntimeClient(server.URL, time.Second)
	manifest := &ToolManifest{Schema: ToolManifestSchemaV2, Tools: []ToolDefinition{{Name: "local.echo", Source: "local", OperationClass: "write"}}}
	if err := client.SyncTools(context.Background(), "test-token", manifest); err != nil {
		t.Fatalf("legacy v2 sync: %v", err)
	}
}

func TestSyncToolsAcceptsNegotiatedV3(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept"); got != "application/json, application/vnd.kei.tool-manifest.v3+json" {
			t.Fatalf("Accept = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(ToolManifestProtocolHeader, ToolManifestSchemaV3)
		w.Header().Set(ToolManifestSupportedHeader, ToolManifestSchemaV2+", "+ToolManifestSchemaV3)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := NewRuntimeClient(server.URL, time.Second)
	manifest := &ToolManifest{Schema: ToolManifestSchemaV3, Tools: []ToolDefinition{{
		Name: "local.echo", Service: "harness", Source: "local", OperationClass: "write",
		Route: &ToolRoute{HarnessExecutor: &HarnessExecutorRoute{Executor: "harness", Registration: "echo"}},
	}}}
	if err := client.SyncTools(context.Background(), "test-token", manifest); err != nil {
		t.Fatalf("negotiated v3 sync: %v", err)
	}
}

func TestSyncToolsRejectsUnsupportedLocalProtocol(t *testing.T) {
	client := NewRuntimeClient("http://unused", time.Second)
	if err := client.SyncTools(context.Background(), "token", &ToolManifest{Schema: "kei.tool-manifest/v5"}); err == nil {
		t.Fatal("unsupported local protocol was sent")
	}
}

func TestSyncToolsConflictIsNonFatal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": "ALREADY_EXISTS", "detail": "tool name conflict"})
	}))
	defer server.Close()

	client := NewRuntimeClient(server.URL, time.Second)
	manifest := &ToolManifest{Schema: ToolManifestSchemaV2, Tools: []ToolDefinition{
		{Name: "conflict.tool", Source: "test", RequiredCapabilities: []string{"r"}, ResourceTypes: []KeiResourceType{{Type: "r"}}, OperationClass: "read"},
	}}
	err := client.SyncTools(context.Background(), "test-token", manifest)
	if err == nil {
		t.Fatal("expected conflict error")
	}
	var syncErr *ToolSyncError
	if !as(err, &syncErr) || !syncErr.Conflict {
		t.Fatalf("unexpected error type: %T %v", err, err)
	}
}

func TestSyncTools500IsNonFatal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewRuntimeClient(server.URL, time.Second)
	manifest := &ToolManifest{Schema: ToolManifestSchemaV2, Tools: []ToolDefinition{
		{Name: "err.tool", Source: "test", RequiredCapabilities: []string{"r"}, ResourceTypes: []KeiResourceType{{Type: "r"}}, OperationClass: "read"},
	}}
	err := client.SyncTools(context.Background(), "test-token", manifest)
	if err == nil {
		t.Fatal("expected error for 500")
	}
	var syncErr *ToolSyncError
	if !as(err, &syncErr) || syncErr.Conflict {
		t.Fatalf("unexpected error type: %T %v", err, err)
	}
}

func TestSyncTools400SurfacesCatalogBodyMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"message": "tool 'codex.shell' is missing a route"})
	}))
	defer server.Close()

	client := NewRuntimeClient(server.URL, time.Second)
	manifest := &ToolManifest{Schema: ToolManifestSchemaV2, Tools: []ToolDefinition{
		{Name: "codex.shell", Source: "test", RequiredCapabilities: []string{"r"}, ResourceTypes: []KeiResourceType{{Type: "r"}}, OperationClass: "read"},
	}}
	err := client.SyncTools(context.Background(), "test-token", manifest)
	if err == nil {
		t.Fatal("expected error for 400")
	}
	if !strings.Contains(err.Error(), "tool 'codex.shell' is missing a route") {
		t.Fatalf("400 error does not surface the catalog body message: %q", err.Error())
	}
}

func TestSyncToolsTransportError(t *testing.T) {
	client := NewRuntimeClient("http://127.0.0.1:1", time.Millisecond)
	manifest := &ToolManifest{Schema: ToolManifestSchemaV2, Tools: []ToolDefinition{
		{Name: "t", Source: "s", RequiredCapabilities: []string{"r"}, ResourceTypes: []KeiResourceType{{Type: "r"}}, OperationClass: "read"},
	}}
	err := client.SyncTools(context.Background(), "token", manifest)
	if err == nil || strings.Contains(err.Error(), "non-fatal") {
		t.Fatalf("expected transport error, got %v", err)
	}
}

func TestSyncToolManifestUnsetEnvSkips(t *testing.T) {
	cfg := Config{
		RuntimeControlPlaneURL: "http://control.example",
		RuntimeToken:           "kh_live_runtime_test_token_1234567890",
		ToolManifestPath:       "",
	}
	var stderr strings.Builder
	syncToolManifest(context.Background(), cfg, time.Second, NewRuntimeClient, &stderr)
	if stderr.Len() != 0 {
		t.Fatalf("expected no output when KEI_TOOL_MANIFEST is empty, got %q", stderr.String())
	}
}

func TestSyncToolManifestMissingFile(t *testing.T) {
	cfg := Config{
		RuntimeControlPlaneURL: "http://control.example",
		RuntimeToken:           "kh_live_runtime_test_token_1234567890",
		ToolManifestPath:       "testdata/nonexistent.json",
	}
	var stderr strings.Builder
	syncToolManifest(context.Background(), cfg, time.Second, NewRuntimeClient, &stderr)
	if !strings.Contains(stderr.String(), "tool manifest") {
		t.Fatalf("expected manifest error on stderr, got %q", stderr.String())
	}
}

func TestSyncToolManifestHTTPErrorLoggedNonFatal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	dir := t.TempDir()
	manifestPath := dir + "/manifest.json"
	if err := os.WriteFile(manifestPath, []byte(`{"schema":"kei.tool-manifest/v2","tools":[{"name":"test.tool","source":"test","required_capabilities":["r"],"resource_types":[{"type":"r"}],"operation_class":"read"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		RuntimeControlPlaneURL: server.URL,
		RuntimeToken:           "test-token",
		ToolManifestPath:       manifestPath,
	}
	var stderr strings.Builder
	syncToolManifest(context.Background(), cfg, time.Second, NewRuntimeClient, &stderr)
	if !strings.Contains(stderr.String(), "tool sync") {
		t.Fatalf("expected tool sync error on stderr, got %q", stderr.String())
	}
}

// as is a convenience wrapper for errors.As used in tests.
func as[T error](err error, target *T) bool {
	return errors.As(err, target)
}
