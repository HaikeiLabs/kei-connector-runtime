package mcproute

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/manifest"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

// UpstreamConfig describes one test connector the way these tests did before
// the route read descriptors from the bundle: testConfig turns it into an mcp
// descriptor of a fake catalog.
type UpstreamConfig struct {
	URL               string
	TokenSource       TokenSource
	ApprovedToolsHash string
	ApprovedTools     []policybundle.MCPApprovedTool
}

// AgentBinding is one test agent_connector_bindings entry.
type AgentBinding struct {
	AgentID     string
	ConnectorID string
}

// testConfig is Config with the connectors given as Upstreams. Unless
// Connectors or AgentBindings is set, every upstream gets an mcp descriptor
// (ID conn-<slug>) bound to the test agent ("test-agent", see testKey).
type testConfig struct {
	KeyRegistry     *KeyRegistry
	Authorizer      Authorizer
	Upstreams       map[string]UpstreamConfig
	Connectors      []policybundle.Connector
	AgentBindings   []AgentBinding
	Logger          *slog.Logger
	UpstreamTimeout time.Duration
}

func (tc testConfig) config() Config {
	connectors := tc.Connectors
	if connectors == nil {
		for slug := range tc.Upstreams {
			connectors = append(connectors, policybundle.Connector{ID: "conn-" + slug, Kind: "mcp", Slug: slug})
		}
	}
	bindings := map[[2]string]bool{}
	if tc.AgentBindings == nil && tc.Connectors == nil {
		for _, c := range connectors {
			bindings[[2]string{"test-agent", c.ID}] = true
		}
	}
	for _, b := range tc.AgentBindings {
		bindings[[2]string{b.AgentID, b.ConnectorID}] = true
	}
	cat := &fakeCatalog{bindings: bindings, digest: "bundle-1"}
	var tokens TokenSource
	for _, c := range connectors {
		if u, ok := tc.Upstreams[c.Slug]; ok {
			c.MCP = &policybundle.MCPDescriptor{URL: u.URL, Transport: "streamable_http", AuthMethod: "oauth", ApprovedManifestHash: u.ApprovedToolsHash, ApprovedTools: u.ApprovedTools}
			if u.TokenSource != nil {
				tokens = u.TokenSource
			}
		}
		cat.connectors = append(cat.connectors, c)
	}
	return Config{KeyRegistry: tc.KeyRegistry, Authorizer: tc.Authorizer, Catalog: cat, TokenSource: tokens, Logger: tc.Logger, UpstreamTimeout: tc.UpstreamTimeout}
}

// buildHandler is NewHandler over a testConfig, with the real SSRF checks.
func buildHandler(tc testConfig) *Handler { return NewHandler(tc.config()) }

// newHandler is buildHandler with the SSRF checks relaxed for loopback test
// servers.
func newHandler(tc testConfig) *Handler {
	h := buildHandler(tc)
	h.checkSSRF = func(u *url.URL) error { return nil }
	h.dialCtl = func(network, address string, c syscall.RawConn) error { return nil }
	return h
}

func newHandlerSSRF(tc testConfig, allowedURLs ...string) *Handler {
	allowed := make(map[string]bool, len(allowedURLs))
	for _, u := range allowedURLs {
		allowed[u] = true
	}
	h := buildHandler(tc)
	h.checkSSRF = func(u *url.URL) error {
		if allowed[u.String()] {
			return nil
		}
		return checkSSRF(u)
	}
	h.dialCtl = func(network, address string, c syscall.RawConn) error { return nil }
	return h
}

// approvedNamed approves namedTool(name) for each name.
func approvedNamed(t *testing.T, names ...string) []policybundle.MCPApprovedTool {
	t.Helper()
	tools := make([]map[string]any, len(names))
	for i, n := range names {
		tools[i] = namedTool(n)
	}
	return approvedTools(t, tools...)
}

// primeListing caches listing as the test session's verified listing for
// slug, as a prior verified tools/list would.
func primeListing(t *testing.T, h *Handler, slug string, listing *verifiedListing) {
	t.Helper()
	d, ok := h.config.Catalog.MCPConnector(slug)
	if !ok {
		t.Fatalf("no mcp descriptor for %s", slug)
	}
	h.mu.Lock()
	h.listings[listingKey{session: "test-session", connector: d.ID}] = &cachedListing{
		listing: listing, bundleDigest: h.config.Catalog.BundleDigest(), approvedHash: d.MCP.ApprovedManifestHash, verifiedAt: h.now(),
	}
	h.mu.Unlock()
}

// testKey creates a KeyRegistry with one minted key and returns both.
func testKey(t *testing.T) (*KeyRegistry, string) {
	t.Helper()
	reg := NewKeyRegistry()
	key, err := reg.Mint(Session{Subject: "test-session", Agent: "test-agent", HarnessKind: "test-harness", SessionID: "test-session"})
	if err != nil {
		t.Fatal(err)
	}
	return reg, key
}

// namedTool is a convenience for creating tool maps in test helpers.
func namedTool(name string) map[string]any {
	return map[string]any{
		"name":        name,
		"description": name,
		"inputSchema": map[string]any{},
	}
}

// hashNamedTools computes the manifest hash for tools created from name/description/inputSchema.
func hashNamedTools(t *testing.T, names ...string) string {
	t.Helper()
	tools := make([]map[string]any, len(names))
	for i, name := range names {
		tools[i] = namedTool(name)
	}
	raw := make([]json.RawMessage, len(tools))
	for i, tool := range tools {
		b, err := json.Marshal(tool)
		if err != nil {
			t.Fatal(err)
		}
		raw[i] = b
	}
	h, err := manifest.Hash(raw)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// primeTools injects a verified listing into the handler cache, simulating a
// prior successful tools/list.
func primeTools(t *testing.T, h *Handler, slug string, names ...string) {
	t.Helper()
	raw := make([]json.RawMessage, len(names))
	for i, name := range names {
		b, err := json.Marshal(namedTool(name))
		if err != nil {
			t.Fatal(err)
		}
		raw[i] = b
	}
	hsh, err := manifest.Hash(raw)
	if err != nil {
		t.Fatal(err)
	}
	listing, err := newVerifiedListing(hsh, raw)
	if err != nil {
		t.Fatal(err)
	}
	primeListing(t, h, slug, listing)
}

type fakeAuthorizer struct{}

func (fakeAuthorizer) Authorize(_ context.Context, d Decision) (Verdict, error) {
	if d.Tool == "X" {
		return Verdict{}, &PermissionError{Reason: "mcp_not_authorized", Tool: d.Tool}
	}
	return Verdict{}, nil
}

func TestMCPRouteAuth_NoKey(t *testing.T) {
	reg, _ := testKey(t)
	h := buildHandler(testConfig{
		KeyRegistry: reg,
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"X"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if hdr := w.Header().Get("WWW-Authenticate"); hdr != "" {
		t.Fatalf("unexpected WWW-Authenticate header: %s", hdr)
	}
	var rpcResp struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	json.Unmarshal(w.Body.Bytes(), &rpcResp)
	if rpcResp.Error == nil || rpcResp.Error.Code != -31401 {
		t.Fatalf("want error code -31401, got %+v", rpcResp.Error)
	}
}

func TestMCPRouteAuth_BadKey(t *testing.T) {
	reg, _ := testKey(t)
	h := buildHandler(testConfig{
		KeyRegistry: reg,
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"X"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer wrong-key")
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if hdr := w.Header().Get("WWW-Authenticate"); hdr != "" {
		t.Fatalf("unexpected WWW-Authenticate header: %s", hdr)
	}
	var rpcResp struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	json.Unmarshal(w.Body.Bytes(), &rpcResp)
	if rpcResp.Error == nil || rpcResp.Error.Code != -31401 {
		t.Fatalf("want error code -31401, got %+v", rpcResp.Error)
	}
}

func TestMCPRouteAuth_ValidKey(t *testing.T) {
	reg, key := testKey(t)
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]any{"content": []any{}},
		})
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: "sha256:dummy"},
		},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"Y","arguments":{}}}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (valid key should proceed)", w.Code)
	}
}

func TestMCPRouteNonLoopback_OriginHeaderDenied(t *testing.T) {
	reg, key := testKey(t)
	h := buildHandler(testConfig{
		KeyRegistry: reg,
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"X"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Origin", "https://evil.com")
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	var rpcResp struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	json.Unmarshal(w.Body.Bytes(), &rpcResp)
	if rpcResp.Error == nil || rpcResp.Error.Code != -31403 {
		t.Fatalf("want error code -31403, got %+v", rpcResp.Error)
	}
}

func TestMCPRouteNonLoopback_NonLocalHostDenied(t *testing.T) {
	reg, key := testKey(t)
	h := buildHandler(testConfig{
		KeyRegistry: reg,
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"X"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "evil.com:8086"
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	var rpcResp struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	json.Unmarshal(w.Body.Bytes(), &rpcResp)
	if rpcResp.Error == nil || rpcResp.Error.Code != -31403 {
		t.Fatalf("want error code -31403, got %+v", rpcResp.Error)
	}
}

func TestMCPRouteNonLoopback_LocalHostAllowed(t *testing.T) {
	reg, key := testKey(t)
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]any{"content": []any{}},
		})
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: "sha256:dummy"},
		},
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"Y"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestMCPRouteAuth_WellKnownReturns404(t *testing.T) {
	reg, _ := testKey(t)
	h := buildHandler(testConfig{
		KeyRegistry: reg,
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestMCPRouteDeniedToolReturnsErrorAndDoesNotReachUpstream(t *testing.T) {
	reg, key := testKey(t)
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]any{"content": []any{}},
		})
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: "sha256:dummy"},
		},
	})
	primeTools(t, h, "test-slug", "X")

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"X","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if upstreamHits.Load() != 0 {
		t.Fatal("upstream was called but should have been blocked by authorization")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (JSON-RPC error delivered as 200)", w.Code)
	}
	var rpcResp struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
		ID any `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rpcResp); err != nil {
		t.Fatalf("decode JSON-RPC response: %v", err)
	}
	if rpcResp.Error == nil {
		t.Fatal("expected JSON-RPC error, got result")
	}
	if rpcResp.Error.Code != -31403 {
		t.Fatalf("error code = %d, want -31403", rpcResp.Error.Code)
	}
	if rpcResp.ID != float64(1) {
		t.Fatalf("error id = %v, want 1", rpcResp.ID)
	}
}

func TestMCPRouteSSRF_PrivateIPBlocked(t *testing.T) {
	reg, key := testKey(t)
	h := buildHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: "https://10.0.0.1/mcp", TokenSource: StaticToken("ct_test"), ApprovedToolsHash: "sha256:dummy"},
		},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	assertDenied(t, w, -31502, "upstream_blocked")
}

func TestMCPRouteSSRF_LoopbackBlocked(t *testing.T) {
	reg, key := testKey(t)
	h := buildHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: "https://127.0.0.1:9999/mcp", TokenSource: StaticToken("ct_test"), ApprovedToolsHash: "sha256:dummy"},
		},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	assertDenied(t, w, -31502, "upstream_blocked")
}

func TestMCPRouteSSRF_NonHTTPSBlocked(t *testing.T) {
	reg, key := testKey(t)
	h := buildHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: "http://example.com/mcp", TokenSource: StaticToken("ct_test"), ApprovedToolsHash: "sha256:dummy"},
		},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	assertDenied(t, w, -31502, "upstream_blocked")
}

func TestMCPRouteForwardsToolsList(t *testing.T) {
	reg, key := testKey(t)
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		if r.Header.Get("Authorization") != "Bearer ct_test" {
			t.Error("upstream did not receive connector token")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]any{
				"tools": []map[string]any{
					namedTool("tool1"),
				},
			},
		})
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: hashNamedTools(t, "tool1"), ApprovedTools: approvedNamed(t, "tool1")},
		},
	})

	body := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if upstreamHits.Load() != 1 {
		t.Fatal("upstream was not called exactly once")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var rpcResp struct {
		Result *json.RawMessage `json:"result"`
		Error  *json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rpcResp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if rpcResp.Error != nil {
		t.Fatalf("unexpected error in response: %s", *rpcResp.Error)
	}
	if rpcResp.Result == nil {
		t.Fatal("expected result, got none")
	}
}

func TestMCPRouteAllowsToolCallToReachUpstream(t *testing.T) {
	reg, key := testKey(t)
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]any{"content": []any{}},
		})
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: "sha256:dummy"},
		},
	})
	primeTools(t, h, "test-slug", "Y")

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"Y","arguments":{}}}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if upstreamHits.Load() != 1 {
		t.Fatal("upstream was not called exactly once")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestMCPRouteStripHarnessAuth(t *testing.T) {
	reg, key := testKey(t)
	var upstreamAuth atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuth.Store(r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]any{"content": []any{}},
		})
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: "sha256:dummy"},
		},
	})
	primeTools(t, h, "test-slug", "Y")

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"Y","arguments":{}}}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	got := upstreamAuth.Load().(string)
	if got != "Bearer ct_test" {
		t.Fatalf("upstream Authorization = %q, want %q", got, "Bearer ct_test")
	}
}

func TestMCPRouteManifestDrift_UnapprovedTool(t *testing.T) {
	reg, key := testKey(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]any{
				"tools": []map[string]any{
					{"name": "tool_unknown", "description": "not approved", "inputSchema": map[string]any{}},
				},
			},
		})
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: hashNamedTools(t, "tool_known"), ApprovedTools: approvedNamed(t, "tool_known")},
		},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	assertNoTools(t, w)
}

func TestMCPRouteManifestDrift_ApprovedToolsPass(t *testing.T) {
	reg, key := testKey(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]any{
				"tools": []map[string]any{
					namedTool("tool_known"),
				},
			},
		})
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: hashNamedTools(t, "tool_known"), ApprovedTools: approvedNamed(t, "tool_known")},
		},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestMCPRouteSSRF_RedirectToBlockedIP(t *testing.T) {
	reg, key := testKey(t)
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		http.Redirect(w, r, "https://10.0.0.1/evil", http.StatusFound)
	}))
	defer upstream.Close()

	h := newHandlerSSRF(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: "sha256:dummy"},
		},
	}, upstream.URL)
	primeTools(t, h, "test-slug", "Y")

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"Y","arguments":{}}}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if upstreamHits.Load() != 1 {
		t.Fatal("upstream was called, but redirect should not have been followed")
	}
	assertDenied(t, w, -31502, "upstream_protocol_error")
}

func TestMCPRouteSSRF_RedirectNotFollowed(t *testing.T) {
	reg, key := testKey(t)
	var targetHits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
	}))
	defer target.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: hashNamedTools(t, "tool1"), ApprovedTools: approvedNamed(t, "tool1")},
		},
	})
	primeTools(t, h, "test-slug", "tool1")

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tool1","arguments":{}}}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if targetHits.Load() != 0 {
		t.Fatalf("redirect target was followed (%d hits); 3xx must fail closed", targetHits.Load())
	}
	assertDenied(t, w, -31502, "upstream_protocol_error")
	var rpcResp struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rpcResp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if rpcResp.Error == nil || rpcResp.Error.Message != "upstream_protocol_error" {
		t.Fatalf("want upstream_protocol_error, got %+v", rpcResp.Error)
	}
}

// assertMCPErrorMessage decodes a JSON-RPC response and asserts its error
// message equals want.
func assertMCPErrorMessage(t *testing.T, body []byte, want string) {
	t.Helper()
	var rpcResp struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		t.Fatalf("decode JSON-RPC response: %v", err)
	}
	if rpcResp.Error == nil {
		t.Fatalf("expected JSON-RPC error, got result: %s", body)
	}
	if rpcResp.Error.Message != want {
		t.Fatalf("error message = %q, want %q", rpcResp.Error.Message, want)
	}
}

func TestMCPRouteConnectorNotFound(t *testing.T) {
	reg, key := testKey(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()

	// The upstream is configured, but no mcp descriptor names this slug
	// (ADR-036 §4.5 step 5).
	h := buildHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: "sha256:dummy"},
		},
		Connectors: []policybundle.Connector{},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tool1","arguments":{}}}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (JSON-RPC error)", w.Code)
	}
	assertMCPErrorMessage(t, w.Body.Bytes(), "connector_not_found")
}

func TestMCPRouteConnectorNotBound(t *testing.T) {
	reg, key := testKey(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()

	// The mcp descriptor names the slug, but the session agent has no
	// agent_connector_bindings entry for it (ADR-036 §4.5 step 6).
	h := buildHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: "sha256:dummy"},
		},
		Connectors: []policybundle.Connector{
			{ID: "conn-1", Kind: "mcp", Slug: "test-slug"},
		},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tool1","arguments":{}}}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (JSON-RPC error)", w.Code)
	}
	assertMCPErrorMessage(t, w.Body.Bytes(), "connector_not_bound")
}

func TestDialControl_BlocksReservedIPs(t *testing.T) {
	tests := []struct {
		addr    string
		blocked bool
	}{
		{"127.0.0.1:443", true},
		{"[::1]:443", true},
		{"10.1.2.3:443", true},
		{"172.16.0.1:443", true},
		{"192.168.1.1:443", true},
		{"[fc00::1]:443", true},
		{"[fd12:3456::1]:443", true},
		{"169.254.169.254:80", true},
		{"[fe80::1]:443", true},
		{"[fe80::1ff:fe28]:443", true},
		{"0.0.0.0:443", true},
		{"[::]:443", true},
		{"0.2.3.4:443", true},
		{"192.0.0.8:443", true},
		{"198.18.0.1:443", true},
		{"198.19.255.254:443", true},
		{"240.0.0.1:443", true},
		{"255.255.255.255:443", true},
		{"[64:ff9b::1]:443", true},
		{"[64:ff9b::ffff:ffff]:443", true},
		{"224.0.0.1:443", true},
		{"239.255.255.254:443", true},
		{"[ff02::1]:443", true},
		{"[64:ff9b:1::1]:443", false},
		{"1.1.1.1:443", false},
		{"8.8.8.8:443", false},
		{"93.184.216.34:443", false},
		{"[2606:4700:4700::1111]:443", false},
		{"[2001:4860:4860::8888]:443", false},
	}
	for _, tt := range tests {
		err := defaultDialControl("tcp", tt.addr, nil)
		if tt.blocked && err == nil {
			t.Errorf("dialControl(%q) = nil, want blocked", tt.addr)
		}
		if !tt.blocked && err != nil {
			t.Errorf("dialControl(%q) = %v, want nil", tt.addr, err)
		}
	}
}

func TestMCPRouteSSE_RelaysEvents(t *testing.T) {
	reg, key := testKey(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("test server does not support flushing")
		}
		w.Write([]byte("event: ping\ndata: {\"foo\":1}\n\n"))
		flusher.Flush()
		w.Write([]byte("event: result\ndata: {\"bar\":2}\n\n"))
		flusher.Flush()
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: hashNamedTools(t, "test_tool"), ApprovedTools: approvedNamed(t, "test_tool")},
		},
	})
	primeTools(t, h, "test-slug", "test_tool")

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test_tool","arguments":{}}}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}
	out := w.Body.String()
	if !strings.Contains(out, "event: ping") {
		t.Fatalf("SSE body missing ping event: %q", out)
	}
	if !strings.Contains(out, "event: result") {
		t.Fatalf("SSE body missing result event: %q", out)
	}
}

func TestMCPRouteResponseBodyRelayed(t *testing.T) {
	reg, key := testKey(t)
	expected := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hello"}]}}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(expected))
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: "sha256:dummy"},
		},
	})
	primeTools(t, h, "test-slug", "Y")

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"Y","arguments":{}}}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if strings.TrimSpace(w.Body.String()) != strings.TrimSpace(expected) {
		t.Fatalf("body = %q, want %q", w.Body.String(), expected)
	}
}

func TestMCPRouteAuth_NilRegistryDenies(t *testing.T) {
	h := buildHandler(testConfig{
		KeyRegistry: nil,
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"X"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	var rpcResp struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	json.Unmarshal(w.Body.Bytes(), &rpcResp)
	if rpcResp.Error == nil || rpcResp.Error.Code != -31401 {
		t.Fatalf("want error code -31401, got %+v", rpcResp.Error)
	}
}

func TestMCPRouteManifestNotApproved_ToolsList(t *testing.T) {
	reg, key := testKey(t)
	h := buildHandler(testConfig{
		KeyRegistry: reg,
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: "https://upstream.example/mcp", TokenSource: StaticToken("ct_test"), ApprovedToolsHash: ""},
		},
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var rpcResp struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
		ID any `json:"id"`
	}
	json.Unmarshal(w.Body.Bytes(), &rpcResp)
	if rpcResp.Error == nil || rpcResp.Error.Message != "mcp_manifest_unapproved" {
		t.Fatalf("want manifest_not_approved, got %+v", rpcResp.Error)
	}
}

func TestMCPRouteManifestNotApproved_ToolsCall(t *testing.T) {
	reg, key := testKey(t)
	h := newHandler(testConfig{
		KeyRegistry: reg,
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: "https://upstream.example/mcp", TokenSource: StaticToken("ct_test"), ApprovedToolsHash: ""},
		},
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"X"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var rpcResp struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
		ID any `json:"id"`
	}
	json.Unmarshal(w.Body.Bytes(), &rpcResp)
	if rpcResp.Error == nil || rpcResp.Error.Message != "mcp_manifest_unapproved" {
		t.Fatalf("want manifest_not_approved, got %+v", rpcResp.Error)
	}
}

type selectiveAuthorizer struct {
	allowed []string
}

func (s selectiveAuthorizer) Authorize(_ context.Context, d Decision) (Verdict, error) {
	for _, a := range s.allowed {
		if d.Tool == a {
			return Verdict{}, nil
		}
	}
	return Verdict{}, &PermissionError{Reason: "mcp_not_authorized", Tool: d.Tool}
}

func TestMCPRouteFilterTools_RemovesDeniedTools(t *testing.T) {
	reg, key := testKey(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]any{
				"tools": []map[string]any{
					namedTool("tool_a"),
					namedTool("tool_b"),
					namedTool("tool_c"),
				},
			},
		})
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  selectiveAuthorizer{allowed: []string{"tool_a", "tool_c"}},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: hashNamedTools(t, "tool_a", "tool_b", "tool_c"), ApprovedTools: approvedNamed(t, "tool_a", "tool_b", "tool_c")},
		},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var rpcResp struct {
		Result *struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rpcResp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if rpcResp.Result == nil {
		t.Fatal("expected result")
	}
	if len(rpcResp.Result.Tools) != 2 {
		t.Fatalf("got %d tools, want 2", len(rpcResp.Result.Tools))
	}
	if rpcResp.Result.Tools[0].Name != "tool_a" {
		t.Fatalf("first tool = %q, want tool_a", rpcResp.Result.Tools[0].Name)
	}
	if rpcResp.Result.Tools[1].Name != "tool_c" {
		t.Fatalf("second tool = %q, want tool_c", rpcResp.Result.Tools[1].Name)
	}
}

func TestMCPRouteFilterTools_AllDenied(t *testing.T) {
	reg, key := testKey(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]any{
				"tools": []map[string]any{
					namedTool("tool_a"),
					namedTool("tool_b"),
				},
			},
		})
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  selectiveAuthorizer{allowed: []string{}},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: hashNamedTools(t, "tool_a", "tool_b"), ApprovedTools: approvedNamed(t, "tool_a", "tool_b")},
		},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var rpcResp struct {
		Result *struct {
			Tools []json.RawMessage `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rpcResp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if rpcResp.Result == nil {
		t.Fatal("expected result")
	}
	if len(rpcResp.Result.Tools) != 0 {
		t.Fatalf("got %d tools, want 0 (all denied)", len(rpcResp.Result.Tools))
	}
}

func TestMCPRouteFilterTools_SSE(t *testing.T) {
	reg, key := testKey(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		tools := []map[string]any{namedTool("tool_a"), namedTool("tool_b"), namedTool("tool_c")}
		msg, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"tools": tools}})
		fmt.Fprintf(w, "event: message\ndata: %s\n\n", msg)
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  selectiveAuthorizer{allowed: []string{"tool_a", "tool_c"}},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: hashNamedTools(t, "tool_a", "tool_b", "tool_c"), ApprovedTools: approvedNamed(t, "tool_a", "tool_b", "tool_c")},
		},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (SSE tools/list filtered)", w.Code)
	}
	var rpcResp struct {
		Result *struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rpcResp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if rpcResp.Result == nil {
		t.Fatal("expected result")
	}
	if len(rpcResp.Result.Tools) != 2 {
		t.Fatalf("got %d tools, want 2", len(rpcResp.Result.Tools))
	}
	if rpcResp.Result.Tools[0].Name != "tool_a" {
		t.Fatalf("first tool = %q, want tool_a", rpcResp.Result.Tools[0].Name)
	}
	if rpcResp.Result.Tools[1].Name != "tool_c" {
		t.Fatalf("second tool = %q, want tool_c", rpcResp.Result.Tools[1].Name)
	}
}

type subjectFilterAuthorizer struct {
	allow func(Decision) error
}

func (s subjectFilterAuthorizer) Authorize(ctx context.Context, d Decision) (Verdict, error) {
	return Verdict{}, s.allow(d)
}

func TestMCPRouteFilterTools_SubjectAware(t *testing.T) {
	reg := NewKeyRegistry()
	key1, err := reg.Mint(Session{Subject: "session-alpha", Agent: "test-agent", HarnessKind: "harness-kind", SessionID: "session-alpha"})
	if err != nil {
		t.Fatal(err)
	}
	key2, err := reg.Mint(Session{Subject: "session-beta", Agent: "test-agent", HarnessKind: "harness-kind", SessionID: "session-beta"})
	if err != nil {
		t.Fatal(err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]any{
				"tools": []map[string]any{
					namedTool("tool_a"),
					namedTool("tool_b"),
					namedTool("tool_c"),
				},
			},
		})
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer: subjectFilterAuthorizer{allow: func(d Decision) error {
			switch d.Subject {
			case "session-alpha":
				if d.Tool == "tool_b" {
					return &PermissionError{Reason: "mcp_not_authorized", Tool: d.Tool}
				}
				return nil
			case "session-beta":
				if d.Tool != "tool_b" {
					return &PermissionError{Reason: "mcp_not_authorized", Tool: d.Tool}
				}
				return nil
			default:
				return &PermissionError{Reason: "mcp_not_authorized", Tool: d.Tool}
			}
		}},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: hashNamedTools(t, "tool_a", "tool_b", "tool_c"), ApprovedTools: approvedNamed(t, "tool_a", "tool_b", "tool_c")},
		},
	})

	for _, tc := range []struct {
		name    string
		key     string
		wantLen int
		want    []string
	}{
		{name: "session-alpha", key: key1, wantLen: 2, want: []string{"tool_a", "tool_c"}},
		{name: "session-beta", key: key2, wantLen: 1, want: []string{"tool_b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tc.key)
			req.Host = "127.0.0.1:8086"
			h.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", w.Code)
			}
			var rpcResp struct {
				Result *struct {
					Tools []struct {
						Name string `json:"name"`
					} `json:"tools"`
				} `json:"result"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &rpcResp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if rpcResp.Result == nil {
				t.Fatal("expected result")
			}
			if len(rpcResp.Result.Tools) != tc.wantLen {
				t.Fatalf("got %d tools, want %d", len(rpcResp.Result.Tools), tc.wantLen)
			}
			for i, name := range tc.want {
				if rpcResp.Result.Tools[i].Name != name {
					t.Fatalf("tool[%d] = %q, want %q", i, rpcResp.Result.Tools[i].Name, name)
				}
			}
		})
	}
}

func TestMCPRouteCall_PassesSubjectAndArgs(t *testing.T) {
	reg, key := testKey(t)
	var got Decision
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]any{"content": []any{}},
		})
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer: subjectFilterAuthorizer{allow: func(d Decision) error {
			got = d
			return nil
		}},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: "sha256:dummy"},
		},
	})
	primeTools(t, h, "test-slug", "my_tool")

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"my_tool","arguments":{"query":"hello"}}}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got.Subject != "test-session" {
		t.Fatalf("Subject = %q, want %q", got.Subject, "test-session")
	}
	if got.Agent != "test-agent" {
		t.Fatalf("Agent = %q, want %q", got.Agent, "test-agent")
	}
	if got.HarnessKind != "test-harness" {
		t.Fatalf("HarnessKind = %q, want %q", got.HarnessKind, "test-harness")
	}
	if got.ConnectorSlug != "test-slug" {
		t.Fatalf("ConnectorSlug = %q, want %q", got.ConnectorSlug, "test-slug")
	}
	if got.Tool != "my_tool" {
		t.Fatalf("Tool = %q, want %q", got.Tool, "my_tool")
	}
	if got.Args == nil {
		t.Fatal("Args is nil, expected raw params")
	}
}

func TestMCPRouteNilAuthorizer_DeniesToolsCall(t *testing.T) {
	reg, key := testKey(t)
	h := newHandler(testConfig{
		KeyRegistry: reg,
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: "https://upstream.example/mcp", TokenSource: StaticToken("ct_test"), ApprovedToolsHash: "sha256:dummy"},
		},
	})
	primeTools(t, h, "test-slug", "tool1")

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tool1"}}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (JSON-RPC error)", w.Code)
	}
	var rpcResp struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	json.Unmarshal(w.Body.Bytes(), &rpcResp)
	if rpcResp.Error == nil {
		t.Fatal("expected error from nil authorizer")
	}
	if rpcResp.Error.Code != -31403 {
		t.Fatalf("error code = %d, want -31403", rpcResp.Error.Code)
	}
}

func TestMCPRouteNilAuthorizer_ToolsListReturnsEmpty(t *testing.T) {
	reg, key := testKey(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]any{
				"tools": []map[string]any{
					namedTool("tool_a"),
				},
			},
		})
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: hashNamedTools(t, "tool_a"), ApprovedTools: approvedNamed(t, "tool_a")},
		},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var rpcResp struct {
		Result *struct {
			Tools []json.RawMessage `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rpcResp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if rpcResp.Result == nil {
		t.Fatal("expected result from upstream even with nil authorizer")
	}
	if len(rpcResp.Result.Tools) != 0 {
		t.Fatalf("got %d tools, want 0 (nil authorizer must deny all)", len(rpcResp.Result.Tools))
	}
}

func TestMCPRouteFilterTools_PreservesNextCursor(t *testing.T) {
	reg, key := testKey(t)
	var callCount int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		if callCount == 1 {
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      1,
				"result": map[string]any{
					"tools": []map[string]any{
						namedTool("tool_a"),
						namedTool("tool_b"),
						namedTool("tool_c"),
					},
					"nextCursor": "abc123",
				},
			})
		} else {
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      2,
				"result": map[string]any{
					"tools": []map[string]any{
						namedTool("tool_d"),
					},
				},
			})
		}
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  selectiveAuthorizer{allowed: []string{"tool_a", "tool_c"}},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: hashNamedTools(t, "tool_a", "tool_b", "tool_c", "tool_d"), ApprovedTools: approvedNamed(t, "tool_a", "tool_b", "tool_c", "tool_d")},
		},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if callCount != 2 {
		t.Fatalf("upstream called %d times, want 2", callCount)
	}
	var rpcResp struct {
		Result *struct {
			Tools      []json.RawMessage `json:"tools"`
			NextCursor string            `json:"nextCursor"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rpcResp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if rpcResp.Result == nil {
		t.Fatal("expected result")
	}
	if len(rpcResp.Result.Tools) != 2 {
		t.Fatalf("got %d tools, want 2", len(rpcResp.Result.Tools))
	}
	if rpcResp.Result.NextCursor != "" {
		t.Fatalf("nextCursor = %q, want empty (all pages consumed)", rpcResp.Result.NextCursor)
	}
}

func TestMCPRouteSSE_ManifestDrift(t *testing.T) {
	reg, key := testKey(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		tools := []map[string]any{{"name": "tool_unknown", "description": "not approved", "inputSchema": map[string]any{}}}
		msg, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"tools": tools}})
		fmt.Fprintf(w, "event: message\ndata: %s\n\n", msg)
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: hashNamedTools(t, "tool_known"), ApprovedTools: approvedNamed(t, "tool_known")},
		},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	assertNoTools(t, w)
}

// subjectTokenSource returns a different token per subject.
type subjectTokenSource struct {
	mu     sync.Mutex
	tokens map[string]string
}

func (s *subjectTokenSource) Token(_ context.Context, subject, _ string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tok, ok := s.tokens[subject]
	if !ok {
		return "", fmt.Errorf("no token for subject %q", subject)
	}
	return tok, nil
}

func TestMCPRouteTokenSource_SubjectSpecific(t *testing.T) {
	reg := NewKeyRegistry()
	keyAlpha, err := reg.Mint(Session{Subject: "session-alpha", Agent: "test-agent", HarnessKind: "harness1", SessionID: "session-alpha"})
	if err != nil {
		t.Fatal(err)
	}
	keyBeta, err := reg.Mint(Session{Subject: "session-beta", Agent: "test-agent", HarnessKind: "harness1", SessionID: "session-beta"})
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var authHeaders []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]any{"tools": []map[string]any{namedTool("tool1")}},
		})
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {
				URL:               upstream.URL,
				TokenSource:       &subjectTokenSource{tokens: map[string]string{"session-alpha": "token_alpha", "session-beta": "token_beta"}},
				ApprovedToolsHash: hashNamedTools(t, "tool1"), ApprovedTools: approvedNamed(t, "tool1"),
			},
		},
	})

	for _, tc := range []struct{ name, key, want string }{
		{"alpha", keyAlpha, "Bearer token_alpha"},
		{"beta", keyBeta, "Bearer token_beta"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tc.key)
			req.Host = "127.0.0.1:8086"
			h.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", w.Code)
			}
		})
	}

	if len(authHeaders) != 2 {
		t.Fatalf("got %d upstream requests, want 2", len(authHeaders))
	}
	if authHeaders[0] != "Bearer token_alpha" {
		t.Errorf("first auth header = %q, want %q", authHeaders[0], "Bearer token_alpha")
	}
	if authHeaders[1] != "Bearer token_beta" {
		t.Errorf("second auth header = %q, want %q", authHeaders[1], "Bearer token_beta")
	}
}

// errTokenSource always returns an error.
type errTokenSource struct{}

func (errTokenSource) Token(_ context.Context, _, _ string) (string, error) {
	return "", fmt.Errorf("token service unavailable")
}

func TestMCPRouteTokenSource_ErrorDeniesUpstream(t *testing.T) {
	reg, key := testKey(t)
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]any{"content": []any{}},
		})
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: errTokenSource{}, ApprovedToolsHash: "sha256:dummy"},
		},
	})
	primeTools(t, h, "test-slug", "tool1")

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tool1","arguments":{}}}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if upstreamHits.Load() != 0 {
		t.Fatal("upstream was contacted despite TokenSource error")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (JSON-RPC error)", w.Code)
	}
	var rpcResp struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rpcResp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if rpcResp.Error == nil {
		t.Fatal("expected JSON-RPC error, got result")
	}
	if rpcResp.Error.Code != -31424 {
		t.Fatalf("error code = %d, want -31424", rpcResp.Error.Code)
	}
}

func TestMCPRouteTokenSource_TokenNotInLogs(t *testing.T) {
	reg, key := testKey(t)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	const sentinelToken = "s3kr1t-t0k3n"

	// Upstream that returns an error so something is logged.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"internal"}}`))
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Logger:      logger,
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken(sentinelToken), ApprovedToolsHash: "sha256:dummy"},
		},
	})
	primeTools(t, h, "test-slug", "tool1")

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tool1","arguments":{}}}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	logOutput := logBuf.String()
	if strings.Contains(logOutput, sentinelToken) {
		t.Errorf("token leaked into log output:\n%s", logOutput)
	}
}

func TestMCPRouteManifestDrift_DescriptionChange(t *testing.T) {
	reg, key := testKey(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]any{
				"tools": []map[string]any{
					{"name": "tool1", "description": "changed description", "inputSchema": map[string]any{}},
				},
			},
		})
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: hashNamedTools(t, "tool1"), ApprovedTools: approvedNamed(t, "tool1")},
		},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	assertNoTools(t, w)
}

// ── Method whitelist ────────────────────────────────────────────────────────────

func TestMCPRoute_UnknownMethodReturnsMinus32601(t *testing.T) {
	reg, key := testKey(t)
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: "sha256:dummy"},
		},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"test://x"}}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if upstreamHits.Load() != 0 {
		t.Fatal("upstream was called but should have been blocked by method whitelist")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (JSON-RPC error delivered as 200)", w.Code)
	}
	var rpcResp struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
		ID any `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rpcResp); err != nil {
		t.Fatalf("decode JSON-RPC response: %v", err)
	}
	if rpcResp.Error == nil {
		t.Fatal("expected JSON-RPC error, got result")
	}
	if rpcResp.Error.Code != -32601 {
		t.Fatalf("error code = %d, want -32601", rpcResp.Error.Code)
	}
}

func TestMCPRoute_PromptsGetReturnsMinus32601(t *testing.T) {
	reg, key := testKey(t)
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: "sha256:dummy"},
		},
	})

	body := `{"jsonrpc":"2.0","id":2,"method":"prompts/get","params":{"name":"x"}}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if upstreamHits.Load() != 0 {
		t.Fatal("upstream was called but should have been blocked by method whitelist")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var rpcResp struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rpcResp); err != nil {
		t.Fatalf("decode JSON-RPC response: %v", err)
	}
	if rpcResp.Error == nil {
		t.Fatal("expected JSON-RPC error, got result")
	}
	if rpcResp.Error.Code != -32601 {
		t.Fatalf("error code = %d, want -32601", rpcResp.Error.Code)
	}
}

func TestMCPRoute_BatchArrayRejected(t *testing.T) {
	reg, key := testKey(t)
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: "sha256:dummy"},
		},
	})

	body := `[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"method":"tools/list"}]`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if upstreamHits.Load() != 0 {
		t.Fatal("upstream was called but batch should be rejected")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var rpcResp struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rpcResp); err != nil {
		t.Fatalf("decode JSON-RPC response: %v", err)
	}
	if rpcResp.Error == nil {
		t.Fatal("expected JSON-RPC error, got result")
	}
}

func TestMCPRoute_InitializeHandledLocally(t *testing.T) {
	reg, key := testKey(t)
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: "sha256:dummy"},
		},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if upstreamHits.Load() != 0 {
		t.Fatal("upstream was called but initialize must be handled locally")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var rpcResp struct {
		Result *json.RawMessage `json:"result"`
		Error  *json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rpcResp); err != nil {
		t.Fatalf("decode JSON-RPC response: %v", err)
	}
	if rpcResp.Error != nil {
		t.Fatalf("unexpected error in initialize response: %s", *rpcResp.Error)
	}
	if rpcResp.Result == nil {
		t.Fatal("expected result from initialize, got none")
	}
}

func TestMCPRoute_PingHandledLocally(t *testing.T) {
	reg, key := testKey(t)
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: "sha256:dummy"},
		},
	})

	body := `{"jsonrpc":"2.0","id":99,"method":"ping"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if upstreamHits.Load() != 0 {
		t.Fatal("upstream was called but ping must be handled locally")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var rpcResp struct {
		Result json.RawMessage  `json:"result"`
		Error  *json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rpcResp); err != nil {
		t.Fatalf("decode JSON-RPC response: %v", err)
	}
	if rpcResp.Error != nil {
		t.Fatalf("unexpected error in ping response: %s", *rpcResp.Error)
	}
	if !bytes.Equal(rpcResp.Result, []byte("{}")) {
		t.Fatalf("ping result = %s, want {} (empty JSON object)", rpcResp.Result)
	}
}

func TestMCPRoute_NotificationInitialized(t *testing.T) {
	reg, key := testKey(t)
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: "sha256:dummy"},
		},
	})

	body := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if upstreamHits.Load() != 0 {
		t.Fatal("upstream was called but notifications/initialized must be handled locally")
	}
}

func TestMCPRouteForwardsReSerializedBody(t *testing.T) {
	reg, key := testKey(t)
	var upstreamHits atomic.Int64
	var receivedBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		b, _ := io.ReadAll(r.Body)
		receivedBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]any{"content": []any{}},
		})
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: hashNamedTools(t, "tool1"), ApprovedTools: approvedNamed(t, "tool1")},
		},
	})
	primeTools(t, h, "test-slug", "tool2")

	// Duplicate "params" key; Go picks the last, upstream must see the same.
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tool1","arguments":{}},"params":{"name":"tool2","arguments":{}}}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if upstreamHits.Load() != 1 {
		t.Fatal("upstream was not called exactly once")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	// The re-serialized body must contain "tool2" (Go's last-value wins)
	// not "tool1" (the first occurrence).
	if !strings.Contains(receivedBody, `"tool2"`) {
		t.Fatalf("re-serialized body = %s, should contain tool2 (last-value wins)", receivedBody)
	}
	if strings.Contains(receivedBody, `"tool1"`) {
		t.Fatalf("re-serialized body = %s, should NOT contain tool1 (duplicate stripped)", receivedBody)
	}
}

func TestMCPRouteManifestDrift_ToolsReorderNoDrift(t *testing.T) {
	reg, key := testKey(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]any{
				"tools": []map[string]any{
					namedTool("tool_b"),
					namedTool("tool_a"),
					namedTool("tool_c"),
				},
			},
		})
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: hashNamedTools(t, "tool_a", "tool_b", "tool_c"), ApprovedTools: approvedNamed(t, "tool_a", "tool_b", "tool_c")},
		},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (reordered tools should not cause drift)", w.Code)
	}
}

func TestMCPRouteManifestDrift_EmptyListFailsClosed(t *testing.T) {
	reg, key := testKey(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]any{"tools": []map[string]any{}},
		})
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: "sha256:whatever"},
		},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	assertNoTools(t, w)
}

func TestMCPRouteManifestDrift_UpstreamErrorFailsClosed(t *testing.T) {
	reg, key := testKey(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"error":   map[string]any{"code": -32603, "message": "internal"},
		})
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: "sha256:whatever"},
		},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	assertDenied(t, w, -31502, "upstream_protocol_error")
}

func TestMCPRouteToolsCall_UnknownToolDenied(t *testing.T) {
	reg, key := testKey(t)
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]any{"content": []any{}},
		})
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: hashNamedTools(t, "tool_known"), ApprovedTools: approvedNamed(t, "tool_known")},
		},
	})
	primeTools(t, h, "test-slug", "tool_known")

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tool_evil","arguments":{}}}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if upstreamHits.Load() != 0 {
		t.Fatal("upstream was called but tool is not in the verified manifest")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (JSON-RPC error)", w.Code)
	}
	var rpcResp struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rpcResp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if rpcResp.Error == nil || rpcResp.Error.Message != "mcp_tool_not_approved" {
		t.Fatalf("want mcp_tool_not_approved, got %+v", rpcResp.Error)
	}
}

// With no cached listing a call first fetches and verifies one (ADR-036
// §5.3). This upstream lists no tools, so the call is never forwarded.
func TestMCPRouteToolsCall_NoVerifiedListingFetchesOneFirst(t *testing.T) {
	reg, key := testKey(t)
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]any{"content": []any{}},
		})
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: hashNamedTools(t, "tool1"), ApprovedTools: approvedNamed(t, "tool1")},
		},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tool1","arguments":{}}}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if upstreamHits.Load() != 1 {
		t.Fatalf("upstream received %d requests, want 1 (the tools/list only)", upstreamHits.Load())
	}
	var rpcResp struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rpcResp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if rpcResp.Error == nil || rpcResp.Error.Message != "mcp_tool_not_approved" {
		t.Fatalf("want mcp_tool_not_approved, got %+v", rpcResp.Error)
	}
}

func TestMCPRouteManifestPaging_TooManyToolsFailsClosed(t *testing.T) {
	reg, key := testKey(t)
	tools := make([]map[string]any, 0, 513)
	for i := 0; i < 513; i++ {
		tools = append(tools, namedTool(fmt.Sprintf("tool_%03d", i)))
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]any{"tools": tools},
		})
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: "sha256:whatever"},
		},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	assertNoTools(t, w)
}

func TestMCPRouteManifestPaging_TooLargeFailsClosed(t *testing.T) {
	reg, key := testKey(t)
	// 512 tools of ~8 KiB each -> ~4 MiB, over the cap.
	big := make([]byte, 8*1024)
	for i := range big {
		big[i] = 'a'
	}
	tools := make([]map[string]any, 0, 512)
	for i := 0; i < 512; i++ {
		tools = append(tools, map[string]any{
			"name":        fmt.Sprintf("tool_%03d", i),
			"description": string(big),
			"inputSchema": map[string]any{},
		})
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]any{"tools": tools},
		})
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: "sha256:whatever"},
		},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	assertNoTools(t, w)
}

func TestMCPRouteManifestPaging_TwoPagesSucceed(t *testing.T) {
	reg, key := testKey(t)
	var mu sync.Mutex
	var cursors []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var req struct {
			Params struct {
				Cursor string `json:"cursor"`
			} `json:"params"`
		}
		json.Unmarshal(b, &req)
		mu.Lock()
		cursors = append(cursors, req.Params.Cursor)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if req.Params.Cursor == "" {
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      1,
				"result": map[string]any{
					"tools":      []map[string]any{namedTool("tool_a"), namedTool("tool_b")},
					"nextCursor": "page2",
				},
			})
		} else {
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      2,
				"result": map[string]any{
					"tools": []map[string]any{namedTool("tool_c")},
				},
			})
		}
	}))
	defer upstream.Close()

	h := newHandler(testConfig{
		KeyRegistry: reg,
		Authorizer:  fakeAuthorizer{},
		Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, TokenSource: StaticToken("ct_test"), ApprovedToolsHash: hashNamedTools(t, "tool_a", "tool_b", "tool_c"), ApprovedTools: approvedNamed(t, "tool_a", "tool_b", "tool_c")},
		},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Host = "127.0.0.1:8086"
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	mu.Lock()
	got := append([]string(nil), cursors...)
	mu.Unlock()
	if len(got) != 2 || got[0] != "" || got[1] != "page2" {
		t.Fatalf("cursor sequence = %v, want [\"\" page2]", got)
	}
	var rpcResp struct {
		Result *struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rpcResp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if rpcResp.Result == nil || len(rpcResp.Result.Tools) != 3 {
		t.Fatalf("got %d tools, want 3 (both pages)", len(rpcResp.Result.Tools))
	}
}
