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
	if err := os.WriteFile(manifestPath, []byte(`{"schema":"kei.tool-manifest/v3","tools":[{"name":"test.tool","service":"test"}]}`), 0644); err != nil {
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

func TestValidateToolManifestV2MissingSource(t *testing.T) {
	m := &ToolManifest{
		Schema: ToolManifestSchemaV2,
		Tools: []ToolDefinition{
			{Name: "test.tool", RequiredCapabilities: []string{"r"}, ResourceTypes: []KeiResourceType{{Type: "r"}}, OperationClass: "read"},
		},
	}
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "source is required") {
		t.Fatalf("expected source-required error, got %v", err)
	}
}

func TestValidateToolManifestV2MissingCapabilities(t *testing.T) {
	m := &ToolManifest{
		Schema: ToolManifestSchemaV2,
		Tools: []ToolDefinition{
			{Name: "test.tool", Source: "github", ResourceTypes: []KeiResourceType{{Type: "r"}}, OperationClass: "read"},
		},
	}
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "required_capabilities") {
		t.Fatalf("expected capabilities-required error, got %v", err)
	}
}

func TestValidateToolManifestV2MissingResourceTypes(t *testing.T) {
	m := &ToolManifest{
		Schema: ToolManifestSchemaV2,
		Tools: []ToolDefinition{
			{Name: "test.tool", Source: "github", RequiredCapabilities: []string{"r"}, OperationClass: "read"},
		},
	}
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "resource_types") {
		t.Fatalf("expected resource_types-required error, got %v", err)
	}
}

func TestValidateToolManifestV2MissingOperationClass(t *testing.T) {
	m := &ToolManifest{
		Schema: ToolManifestSchemaV2,
		Tools: []ToolDefinition{
			{Name: "test.tool", Source: "github", RequiredCapabilities: []string{"r"}, ResourceTypes: []KeiResourceType{{Type: "r"}}},
		},
	}
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "operation_class") {
		t.Fatalf("expected operation_class-required error, got %v", err)
	}
}

func TestValidateToolManifestV2InvalidOperationClass(t *testing.T) {
	m := &ToolManifest{
		Schema: ToolManifestSchemaV2,
		Tools: []ToolDefinition{
			{Name: "test.tool", Source: "github", RequiredCapabilities: []string{"r"}, ResourceTypes: []KeiResourceType{{Type: "r"}}, OperationClass: "delete"},
		},
	}
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "invalid operation_class") {
		t.Fatalf("expected invalid operation_class error, got %v", err)
	}
}

func TestValidateToolManifestV2InvalidSource(t *testing.T) {
	m := &ToolManifest{
		Schema: ToolManifestSchemaV2,
		Tools: []ToolDefinition{
			{Name: "test.tool", Source: "UPPERCASE", RequiredCapabilities: []string{"r"}, ResourceTypes: []KeiResourceType{{Type: "r"}}, OperationClass: "read"},
		},
	}
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "invalid source") {
		t.Fatalf("expected invalid source error, got %v", err)
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

func TestValidateToolManifestDuplicateNames(t *testing.T) {
	m := &ToolManifest{
		Tools: []ToolDefinition{
			{Name: "foo.bar", Source: "foo", RequiredCapabilities: []string{"r"}, ResourceTypes: []KeiResourceType{{Type: "r"}}, OperationClass: "read", Description: "first"},
			{Name: "foo.bar", Source: "foo", RequiredCapabilities: []string{"r"}, ResourceTypes: []KeiResourceType{{Type: "r"}}, OperationClass: "read", Description: "second"},
		},
	}
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "duplicate name") {
		t.Fatalf("expected duplicate-name error, got %v", err)
	}
}

func TestValidateToolManifestTooManyTools(t *testing.T) {
	tools := make([]ToolDefinition, 257)
	for i := range tools {
		tools[i] = ToolDefinition{Name: "t", Service: "s"}
	}
	m := &ToolManifest{Tools: tools}
	err := validateToolManifest(m)
	if err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("expected too-many error, got %v", err)
	}
}

func TestValidateToolManifestEmptyName(t *testing.T) {
	m := &ToolManifest{
		Tools: []ToolDefinition{{Name: "", Service: "s"}},
	}
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "name is required") {
		t.Fatalf("expected name-required error, got %v", err)
	}
}

func TestValidateToolManifestInvalidName(t *testing.T) {
	m := &ToolManifest{
		Tools: []ToolDefinition{{Name: "has space", Service: "s"}},
	}
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "invalid name") {
		t.Fatalf("expected invalid-name error, got %v", err)
	}
}

func TestValidateToolManifestInvalidService(t *testing.T) {
	m := &ToolManifest{
		Tools: []ToolDefinition{
			{Name: "t", Source: "s", RequiredCapabilities: []string{"r"}, ResourceTypes: []KeiResourceType{{Type: "r"}}, OperationClass: "read", Service: "bad service"},
		},
	}
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "invalid service") {
		t.Fatalf("expected invalid-service error, got %v", err)
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
		var body ToolManifest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body.Tools) != 1 || body.Tools[0].Name != "test.tool" {
			t.Fatalf("unexpected body: %+v", body)
		}
		routes["PUT /api/v1/runtime/tools"]++
		w.Header().Set("Content-Type", "application/json")
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
