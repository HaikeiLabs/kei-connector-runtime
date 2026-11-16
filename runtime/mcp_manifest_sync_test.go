package runtime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type mcpSyncTestConfig struct {
	token string
	url   string
	state string
}

func (c mcpSyncTestConfig) PolicyStateDir() string     { return c.state }
func (c mcpSyncTestConfig) Token() string              { return c.token }
func (c mcpSyncTestConfig) ControlPlaneURL() string    { return c.url }
func (c mcpSyncTestConfig) IsProduction() bool         { return false }
func (c mcpSyncTestConfig) Validate() error            { return nil }
func (c mcpSyncTestConfig) IsRuntime() bool            { return true }
func (c mcpSyncTestConfig) PolicyAuditPath() string    { return "" }
func (c mcpSyncTestConfig) PolicyAuditMaxBytes() int64 { return 0 }

const testMCPManifestHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestSubmitMCPManifestUsesScopedRuntimeEndpoint(t *testing.T) {
	var gotPath, gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		var body struct {
			ManifestHash string            `json:"manifest_hash"`
			Tools        []json.RawMessage `json:"tools"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if body.ManifestHash != testMCPManifestHash || len(body.Tools) != 1 {
			t.Errorf("request body = %+v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"manifest_hash":"` + testMCPManifestHash + `","status":"candidate"}`))
	}))
	defer server.Close()

	client := &runtimeClient{baseURL: server.URL, client: server.Client()}
	tools := []json.RawMessage{json.RawMessage(`{"name":"create_issue","description":"Create issue","inputSchema":{"type":"object"}}`)}
	got, err := client.SubmitMCPManifest(context.Background(), "runtime-secret", "org-1", "ws-1", "connector-1", tools, testMCPManifestHash)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "candidate" || got.ManifestHash != testMCPManifestHash {
		t.Fatalf("catalog response = %+v", got)
	}
	wantPath := "/api/v1/organizations/org-1/workspaces/ws-1/data-connectors/connector-1/tool-manifests"
	if gotPath != wantPath || gotAuth != "Bearer runtime-secret" {
		t.Fatalf("request path/auth = %q/%q", gotPath, gotAuth)
	}
}

func TestSubmitMCPManifestDoesNotFollowRedirects(t *testing.T) {
	var redirected bool
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected = true }))
	defer destination.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", destination.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client := &runtimeClient{baseURL: server.URL, client: server.Client()}
	_, err := client.SubmitMCPManifest(context.Background(), "runtime-secret", "org-1", "ws-1", "connector-1", []json.RawMessage{json.RawMessage(`{"name":"create_issue","inputSchema":{}}`)}, testMCPManifestHash)
	if err == nil || redirected {
		t.Fatalf("redirect error=%v destination contacted=%t", err, redirected)
	}
}

func TestSubmitMCPManifestRejectsInvalidCatalogAcknowledgment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"manifest_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","status":"candidate"}`))
	}))
	defer server.Close()
	client := &runtimeClient{baseURL: server.URL, client: server.Client()}
	_, err := client.SubmitMCPManifest(context.Background(), "runtime-secret", "org-1", "ws-1", "connector-1", []json.RawMessage{json.RawMessage(`{"name":"create_issue","inputSchema":{}}`)}, testMCPManifestHash)
	if err == nil || !strings.Contains(err.Error(), "invalid MCP manifest acknowledgment") {
		t.Fatalf("error = %v, want invalid acknowledgment", err)
	}
}

func TestMCPManifestSyncIsLocalSocketOnlyAndAcceptsOwnerSocketWithoutRuntimeToken(t *testing.T) {
	cfg := mcpSyncTestConfig{token: "runtime-secret", url: "https://catalog.example"}
	l := NewLocalPDP(cfg, nil)
	checkConfig := func() error { return nil }
	checkAuth := func(*http.Request) bool { return false }
	body := `{"schema":"kei.mcp-manifest-sync-request/v1","server_slug":"linear","tools":[{"name":"create_issue","description":"Create issue","inputSchema":{"type":"object"}}]}`

	socketHandler := l.NewSocketHandler(http.NotFoundHandler(), checkConfig, checkAuth)
	socketResponse := httptest.NewRecorder()
	socketRequest := httptest.NewRequest(http.MethodPost, mcpManifestSyncPath, strings.NewReader(body))
	socketHandler.ServeHTTP(socketResponse, socketRequest)
	if socketResponse.Code != http.StatusServiceUnavailable || !strings.Contains(socketResponse.Body.String(), "runtime_identity_unavailable") {
		t.Fatalf("owner socket response = %d %s; want handler reached without bearer", socketResponse.Code, socketResponse.Body.String())
	}

	tcpHandler := l.NewHandler(http.NotFoundHandler(), checkConfig, checkAuth)
	tcpResponse := httptest.NewRecorder()
	tcpRequest := httptest.NewRequest(http.MethodPost, mcpManifestSyncPath, strings.NewReader(body))
	tcpHandler.ServeHTTP(tcpResponse, tcpRequest)
	if tcpResponse.Code != http.StatusNotFound {
		t.Fatalf("TCP response = %d; want socket-only route to fall through", tcpResponse.Code)
	}
}

func TestValidMCPManifestHash(t *testing.T) {
	if !validMCPManifestHash(testMCPManifestHash) {
		t.Fatal("expected valid manifest hash")
	}
	for _, invalid := range []string{"", "sha256:ABCDEF", "sha256:" + strings.Repeat("A", 64), "sha256:" + strings.Repeat("g", 64)} {
		if validMCPManifestHash(invalid) {
			t.Errorf("accepted invalid manifest hash %q", invalid)
		}
	}
}
