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

func TestLoadToolManifestHappyPath(t *testing.T) {
	m, err := LoadToolManifest("testdata/tool-manifest.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Tools) != 3 {
		t.Fatalf("tools = %d, want 3", len(m.Tools))
	}
	if m.Tools[0].Name != "github.create_pr" || m.Tools[0].Service != "github" {
		t.Fatalf("tool[0] = %+v", m.Tools[0])
	}
	if m.Schema != ToolManifestSchemaV1 {
		t.Fatalf("schema = %q, want %q", m.Schema, ToolManifestSchemaV1)
	}
}

func TestSyncToolsPassesSchemaThrough(t *testing.T) {
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
	manifest := &ToolManifest{Schema: ToolManifestSchemaV1, Tools: []ToolDefinition{{Name: "test.tool", Service: "test"}}}
	if err := client.SyncTools(context.Background(), "test-token", manifest); err != nil {
		t.Fatal(err)
	}
	if gotSchema != ToolManifestSchemaV1 {
		t.Fatalf("PUT body schema = %q, want %q", gotSchema, ToolManifestSchemaV1)
	}
}

func TestSyncToolManifestUnsupportedSchemaSkips(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dir := t.TempDir()
	manifestPath := dir + "/manifest.json"
	if err := os.WriteFile(manifestPath, []byte(`{"schema":"kei.tool-manifest/v2","tools":[{"name":"test.tool","service":"test"}]}`), 0644); err != nil {
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
	if err := os.WriteFile(path, []byte(`{"tools":[]}`), 0644); err != nil {
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
	if err := os.WriteFile(path, []byte(`{"tools":null}`), 0644); err != nil {
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
			{Name: "foo.bar", Service: "foo", Description: "first"},
			{Name: "foo.bar", Service: "foo", Description: "second"},
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
		Tools: []ToolDefinition{{Name: "t", Service: ""}},
	}
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "service is required") {
		t.Fatalf("expected service-required error, got %v", err)
	}
}

func TestValidateToolManifestTooManyResources(t *testing.T) {
	resources := make([]string, 33)
	for i := range resources {
		resources[i] = "r"
	}
	m := &ToolManifest{
		Tools: []ToolDefinition{{Name: "t", Service: "s", Resources: resources}},
	}
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "too many resources") {
		t.Fatalf("expected too-many-resources error, got %v", err)
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
	manifest := &ToolManifest{Tools: []ToolDefinition{{Name: "test.tool", Service: "test"}}}
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
	manifest := &ToolManifest{Tools: []ToolDefinition{{Name: "conflict.tool", Service: "test"}}}
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
	manifest := &ToolManifest{Tools: []ToolDefinition{{Name: "err.tool", Service: "test"}}}
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
	manifest := &ToolManifest{Tools: []ToolDefinition{{Name: "t", Service: "s"}}}
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
	if err := os.WriteFile(manifestPath, []byte(`{"tools":[{"name":"test.tool","service":"test"}]}`), 0644); err != nil {
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
