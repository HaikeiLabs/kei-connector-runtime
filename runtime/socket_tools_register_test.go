package runtime_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	connectorruntime "github.com/HaikeiLabs/kei-connector-runtime"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

// fakeToolRegistrar implements keiruntime.ToolRegistrar for testing.
type fakeToolRegistrar struct {
	lastManifest *keiruntime.ToolManifest
	lastToken    string
	response     *keiruntime.ToolSyncResponse
	err          error
}

func (f *fakeToolRegistrar) RegisterTools(ctx context.Context, token string, manifest *keiruntime.ToolManifest) (*keiruntime.ToolSyncResponse, error) {
	f.lastToken = token
	f.lastManifest = manifest
	return f.response, f.err
}

func TestSocketToolsRegisterValidManifest(t *testing.T) {
	registrar := &fakeToolRegistrar{
		response: &keiruntime.ToolSyncResponse{Added: 3, Updated: 1, Removed: 0, Unchanged: 5},
	}
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           "test-token",
		RuntimeControlPlaneURL: "https://kei.example",
	}, nil)
	l.SetToolRegistrar(registrar)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	handler := l.NewHandler(next, func() error { return nil }, func(r *http.Request) bool { return true })

	body := `{"schema":"kei.tool-manifest/v3","tools":[{"name":"test.tool","service":"test","source":"test","operation_class":"read","route":{"harness_executor":{"executor":"test","registration":"test.tool"}}}]}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/tools:register", strings.NewReader(body))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp keiruntime.ToolSyncResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Added != 3 || resp.Updated != 1 || resp.Removed != 0 || resp.Unchanged != 5 {
		t.Fatalf("unexpected counts: %+v", resp)
	}
	if registrar.lastToken != "test-token" {
		t.Fatalf("registrar token = %q, want test-token", registrar.lastToken)
	}
	if registrar.lastManifest == nil || registrar.lastManifest.Schema != "kei.tool-manifest/v3" {
		t.Fatalf("registrar did not receive manifest")
	}
	// Confirm the full manifest was passed through.
	if len(registrar.lastManifest.Tools) != 1 || registrar.lastManifest.Tools[0].Name != "test.tool" {
		t.Fatalf("registrar manifest tools = %+v", registrar.lastManifest.Tools)
	}
}

func TestSocketToolsRegisterAcceptsV3Only(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantStatus int
		wantSchema string
		wantError  string
	}{
		{"v3", `{"schema":"kei.tool-manifest/v3","tools":[{"name":"test.tool","service":"test","source":"test","operation_class":"read","route":{"harness_executor":{"executor":"test","registration":"test.tool"}}}]}`, http.StatusOK, "kei.tool-manifest/v3", ""},
		{"v1", `{"schema":"kei.tool-manifest/v1","tools":[]}`, http.StatusBadRequest, "", `unsupported tool manifest schema: supported kei.tool-manifest/v3, received "kei.tool-manifest/v1"`},
		{"v2", `{"schema":"kei.tool-manifest/v2","tools":[]}`, http.StatusBadRequest, "", `unsupported tool manifest schema: supported kei.tool-manifest/v3, received "kei.tool-manifest/v2"`},
		{"v4", `{"schema":"kei.tool-manifest/v4","tools":[]}`, http.StatusBadRequest, "", `unsupported tool manifest schema: supported kei.tool-manifest/v3, received "kei.tool-manifest/v4"`},
		{"garbage", `{"schema":"whatever","tools":[]}`, http.StatusBadRequest, "", `unsupported tool manifest schema: supported kei.tool-manifest/v3, received "whatever"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			registrar := &fakeToolRegistrar{response: &keiruntime.ToolSyncResponse{}}
			l := keiruntime.NewLocalPDP(connectorruntime.Config{RuntimeToken: "test-token", RuntimeControlPlaneURL: "https://kei.example"}, nil)
			l.SetToolRegistrar(registrar)
			handler := l.NewHandler(http.NotFoundHandler(), func() error { return nil }, func(r *http.Request) bool { return true })
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/tools:register", strings.NewReader(tc.body)))
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantError != "" {
				var response struct {
					Error struct {
						Message string `json:"message"`
					} `json:"error"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
					t.Fatalf("decode error response: %v", err)
				}
				if !strings.Contains(response.Error.Message, tc.wantError) {
					t.Fatalf("error message = %q, want containing %q", response.Error.Message, tc.wantError)
				}
			}
			if tc.wantSchema != "" && (registrar.lastManifest == nil || registrar.lastManifest.Schema != tc.wantSchema) {
				t.Fatalf("registrar manifest = %+v, want schema %q", registrar.lastManifest, tc.wantSchema)
			}
		})
	}
}

func TestSocketToolsRegisterCatalog400(t *testing.T) {
	registrar := &fakeToolRegistrar{
		err: &keiruntime.ToolSyncError{StatusCode: http.StatusBadRequest, Message: "invalid tool definition: tools[0]: name is required"},
	}
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           "test-token",
		RuntimeControlPlaneURL: "https://kei.example",
	}, nil)
	l.SetToolRegistrar(registrar)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	handler := l.NewHandler(next, func() error { return nil }, func(r *http.Request) bool { return true })

	body := `{"schema":"kei.tool-manifest/v3","tools":[{"name":"test.tool","service":"test","source":"test","operation_class":"read","route":{"harness_executor":{"executor":"test","registration":"test.tool"}}}]}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/tools:register", strings.NewReader(body))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	var errResp struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if errResp.Error.Code != "tool_sync_error" {
		t.Fatalf("error code = %q, want tool_sync_error", errResp.Error.Code)
	}
	if !strings.Contains(errResp.Error.Message, "name is required") {
		t.Fatalf("error message = %q, want catalog message", errResp.Error.Message)
	}
}

func TestSocketToolsRegisterUnsupportedSchema(t *testing.T) {
	registrar := &fakeToolRegistrar{response: &keiruntime.ToolSyncResponse{}}
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           "test-token",
		RuntimeControlPlaneURL: "https://kei.example",
	}, nil)
	l.SetToolRegistrar(registrar)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	handler := l.NewHandler(next, func() error { return nil }, func(r *http.Request) bool { return true })

	// Unsupported schema should be rejected before reaching the registrar.
	body := `{"schema":"kei.tool-manifest/v5","tools":[]}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/tools:register", strings.NewReader(body))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	var errResp struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if errResp.Error.Code != "invalid_manifest" {
		t.Fatalf("error code = %q, want invalid_manifest", errResp.Error.Code)
	}
	if registrar.lastManifest != nil {
		t.Fatal("registrar was called despite unsupported schema")
	}
}

func TestSocketToolsRegisterEmptyToolsV4(t *testing.T) {
	registrar := &fakeToolRegistrar{response: &keiruntime.ToolSyncResponse{}}
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           "test-token",
		RuntimeControlPlaneURL: "https://kei.example",
	}, nil)
	l.SetToolRegistrar(registrar)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	handler := l.NewHandler(next, func() error { return nil }, func(r *http.Request) bool { return true })

	// v4 requires a non-empty tools array.
	body := `{"schema":"kei.tool-manifest/v3","tools":[]}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/tools:register", strings.NewReader(body))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if registrar.lastManifest != nil {
		t.Fatal("registrar was called despite empty v4 tools")
	}
}

func TestSocketToolsRegisterNoRegistrar(t *testing.T) {
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken: "test-token",
	}, nil)
	// No registrar set — the route fails closed with a JSON error.

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	handler := l.NewHandler(next, func() error { return nil }, func(r *http.Request) bool { return true })

	body := `{"schema":"kei.tool-manifest/v3","tools":[{"name":"test.tool","service":"test","source":"test","operation_class":"read","route":{"harness_executor":{"executor":"test","registration":"test.tool"}}}]}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/tools:register", strings.NewReader(body))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "tool_registration_unavailable") {
		t.Fatalf("expected unavailable JSON response, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSocketToolsRegisterNoAuth(t *testing.T) {
	registrar := &fakeToolRegistrar{response: &keiruntime.ToolSyncResponse{}}
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           "test-token",
		RuntimeControlPlaneURL: "https://kei.example",
	}, nil)
	l.SetToolRegistrar(registrar)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	// checkAuth returns false.
	handler := l.NewHandler(next, func() error { return nil }, func(r *http.Request) bool { return false })

	body := `{"schema":"kei.tool-manifest/v3","tools":[{"name":"test.tool","service":"test","source":"test","operation_class":"read","route":{"harness_executor":{"executor":"test","registration":"test.tool"}}}]}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/tools:register", strings.NewReader(body))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSocketToolsRegisterDoesNotTouchManifestFile(t *testing.T) {
	registrar := &fakeToolRegistrar{
		response: &keiruntime.ToolSyncResponse{Added: 1},
	}
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           "test-token",
		RuntimeControlPlaneURL: "https://kei.example",
	}, nil)
	l.SetToolRegistrar(registrar)

	// Create a temp file to simulate KEI_TOOL_MANIFEST.
	manifestDir := t.TempDir()
	manifestPath := filepath.Join(manifestDir, "manifest.json")
	originalContent := `{"schema":"kei.tool-manifest/v3","tools":[{"name":"original.tool","service":"test","source":"test","operation_class":"read","route":{"harness_executor":{"executor":"test","registration":"original.tool"}}}]}`
	if err := os.WriteFile(manifestPath, []byte(originalContent), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEI_TOOL_MANIFEST", manifestPath)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	handler := l.NewHandler(next, func() error { return nil }, func(r *http.Request) bool { return true })

	body := `{"schema":"kei.tool-manifest/v3","tools":[{"name":"test.tool","service":"test","source":"test","operation_class":"read","route":{"harness_executor":{"executor":"test","registration":"test.tool"}}}]}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/tools:register", strings.NewReader(body))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify the file is unchanged.
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != originalContent {
		t.Fatalf("manifest file changed:\noriginal: %s\ncurrent: %s", originalContent, string(content))
	}
}
