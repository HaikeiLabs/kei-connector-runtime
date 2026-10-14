package mcproute

import (
	"context"
	"encoding/json"
	"net"
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

// fakeCatalog is a bundle view with fixed descriptors and bindings.
type fakeCatalog struct {
	mu         sync.Mutex
	connectors []policybundle.Connector
	bindings   map[[2]string]bool
	digest     string
}

func (c *fakeCatalog) MCPConnector(slug string) (policybundle.Connector, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, d := range c.connectors {
		if d.Kind == "mcp" && d.Slug == slug && d.MCP != nil {
			return d, true
		}
	}
	return policybundle.Connector{}, false
}

func (c *fakeCatalog) AgentBoundToConnector(agentID, connectorID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bindings[[2]string{agentID, connectorID}]
}

func (c *fakeCatalog) MCPHosts() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var hosts []string
	for _, d := range c.connectors {
		if d.Kind == "mcp" && d.MCP != nil {
			u, _ := url.Parse(d.MCP.URL)
			hosts = append(hosts, u.Host)
		}
	}
	return hosts
}

func (c *fakeCatalog) BundleDigest() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.digest
}

func (c *fakeCatalog) setApproval(slug string, approved []policybundle.MCPApprovedTool, digest string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, d := range c.connectors {
		if d.Slug == slug {
			m := *d.MCP
			m.ApprovedTools = approved
			m.ApprovedManifestHash = "sha256:" + digest
			c.connectors[i].MCP = &m
		}
	}
	c.digest = digest
}

// approvedTools returns approved_tools entries whose hashes match the tools.
func approvedTools(t *testing.T, tools ...map[string]any) []policybundle.MCPApprovedTool {
	t.Helper()
	out := make([]policybundle.MCPApprovedTool, 0, len(tools))
	for _, tool := range tools {
		raw, err := json.Marshal(tool)
		if err != nil {
			t.Fatal(err)
		}
		h, err := manifest.ToolHash(raw)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, policybundle.MCPApprovedTool{Name: tool["name"].(string), ToolHash: h})
	}
	return out
}

// catalogFor returns a catalog with one mcp connector, slug test-slug, at
// upstreamURL with the given approval, bound to the test agent.
func catalogFor(upstreamURL string, approved []policybundle.MCPApprovedTool) *fakeCatalog {
	hash := "sha256:approved"
	if approved == nil {
		hash = ""
	}
	return &fakeCatalog{
		connectors: []policybundle.Connector{{ID: "conn-1", Kind: "mcp", Slug: "test-slug", MCP: &policybundle.MCPDescriptor{
			URL: upstreamURL, Transport: "streamable_http", AuthMethod: "oauth", ApprovedManifestHash: hash, ApprovedTools: approved,
		}}},
		bindings: map[[2]string]bool{{"test-agent", "conn-1"}: true},
		digest:   "bundle-1",
	}
}

// listingUpstream answers tools/list with tools() and tools/call with an
// empty result, counting each method.
type listingUpstream struct {
	srv   *httptest.Server
	lists atomic.Int64
	calls atomic.Int64
	mu    sync.Mutex
	tools []map[string]any
	seen  []http.Header
}

func newListingUpstream(t *testing.T, tools ...map[string]any) *listingUpstream {
	t.Helper()
	u := &listingUpstream{tools: tools}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req jsonrpcRequest
		json.NewDecoder(r.Body).Decode(&req)
		u.mu.Lock()
		u.seen = append(u.seen, r.Header.Clone())
		tools := u.tools
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "tools/list":
			u.lists.Add(1)
			json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"tools": tools}})
		default:
			u.calls.Add(1)
			w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`))
		}
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *listingUpstream) setTools(tools ...map[string]any) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.tools = tools
}

// catalogHandler builds a handler over cat with the SSRF checks relaxed for
// the loopback test server and a permissive authorizer.
func catalogHandler(t *testing.T, cat Catalog) (*Handler, *KeyRegistry, string) {
	t.Helper()
	reg, key := testKey(t)
	h := NewHandler(Config{KeyRegistry: reg, Authorizer: fakeAuthorizer{}, Catalog: cat, TokenSource: StaticToken("ct_test")})
	h.checkSSRF = func(*url.URL) error { return nil }
	h.dialCtl = func(string, string, syscall.RawConn) error { return nil }
	return h, reg, key
}

func listNames(t *testing.T, w *httptest.ResponseRecorder) []string {
	t.Helper()
	var resp struct {
		Result *struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.Result == nil {
		t.Fatalf("not a tools/list result: %s", w.Body.Bytes())
	}
	names := []string{}
	for _, tool := range resp.Result.Tools {
		names = append(names, tool.Name)
	}
	return names
}

const listBody = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`

func callBody(tool string) string {
	return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `","arguments":{}}}`
}

func TestMCPRouteCatalog_UpstreamComesFromDescriptor(t *testing.T) {
	a := namedTool("a")
	up := newListingUpstream(t, a)
	h, _, key := catalogHandler(t, catalogFor(up.srv.URL, approvedTools(t, a)))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, listBody))

	if got := listNames(t, w); len(got) != 1 || got[0] != "a" {
		t.Fatalf("tools = %v, want [a] from the descriptor's mcp.url", got)
	}
}

func TestMCPRouteCatalog_SubsetListingIsVerified(t *testing.T) {
	a, b := namedTool("a"), namedTool("b")
	up := newListingUpstream(t, a)
	h, _, key := catalogHandler(t, catalogFor(up.srv.URL, approvedTools(t, a, b)))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, listBody))

	if got := listNames(t, w); len(got) != 1 || got[0] != "a" {
		t.Fatalf("tools = %v, want [a]: a subset of the approved tools is verified (ADR-036 §5.3)", got)
	}
}

func TestMCPRouteCatalog_SupersetIsDriftAndBlocksTheSession(t *testing.T) {
	a, b := namedTool("a"), namedTool("b")
	up := newListingUpstream(t, a, b)
	h, _, key := catalogHandler(t, catalogFor(up.srv.URL, approvedTools(t, a)))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, listBody))
	assertNoTools(t, w)

	lists := up.lists.Load()
	w = httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callBody("a")))
	assertDenied(t, w, -31409, "mcp_manifest_drift")
	if up.calls.Load() != 0 || up.lists.Load() != lists {
		t.Fatalf("a drift-blocked connector reached the upstream (lists %d -> %d, calls %d)", lists, up.lists.Load(), up.calls.Load())
	}
}

func TestMCPRouteCatalog_ChangedToolHashIsDrift(t *testing.T) {
	a := namedTool("a")
	changed := namedTool("a")
	changed["description"] = "now exfiltrates"
	up := newListingUpstream(t, changed)
	h, _, key := catalogHandler(t, catalogFor(up.srv.URL, approvedTools(t, a)))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, listBody))

	assertNoTools(t, w)
}

// An unapproved connector is never called. tools/list observes its listing
// (to submit it as a candidate, §5.3) and returns none of it.
func TestMCPRouteCatalog_UnapprovedNeverForwardsACall(t *testing.T) {
	up := newListingUpstream(t, namedTool("a"))
	h, _, key := catalogHandler(t, catalogFor(up.srv.URL, nil))

	for _, body := range []string{listBody, callBody("a")} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, routeRequest(key, body))
		assertDenied(t, w, -31409, "mcp_manifest_unapproved")
	}
	if up.calls.Load() != 0 || up.lists.Load() != 1 {
		t.Fatalf("lists %d calls %d: want the one observing tools/list and no tools/call", up.lists.Load(), up.calls.Load())
	}
}

func TestMCPRouteCatalog_ConnectorNotFoundAndNotBound(t *testing.T) {
	up := newListingUpstream(t, namedTool("a"))
	cat := catalogFor(up.srv.URL, approvedTools(t, namedTool("a")))
	h, reg, key := catalogHandler(t, cat)

	req := routeRequest(key, callBody("a"))
	req.URL.Path = "/mcp/other-slug"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assertDenied(t, w, -31403, "connector_not_found")

	unbound, err := reg.Mint(Session{Subject: "s", Agent: "other-agent", HarnessKind: "claude_code", SessionID: "s2"})
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(unbound, callBody("a")))
	assertDenied(t, w, -31403, "connector_not_bound")
}

func TestMCPRouteCatalog_CallFetchesAListingWhenNoneIsCached(t *testing.T) {
	a := namedTool("a")
	up := newListingUpstream(t, a)
	h, _, key := catalogHandler(t, catalogFor(up.srv.URL, approvedTools(t, a)))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callBody("a")))

	if up.lists.Load() != 1 || up.calls.Load() != 1 {
		t.Fatalf("lists=%d calls=%d, want the call to verify a listing first, then forward; body %s", up.lists.Load(), up.calls.Load(), w.Body.Bytes())
	}
}

func TestMCPRouteCatalog_ListingCachedPerSession(t *testing.T) {
	a := namedTool("a")
	up := newListingUpstream(t, a)
	h, reg, key := catalogHandler(t, catalogFor(up.srv.URL, approvedTools(t, a)))
	other, err := reg.Mint(Session{Subject: "s2", Agent: "test-agent", HarnessKind: "claude_code", SessionID: "session-2"})
	if err != nil {
		t.Fatal(err)
	}

	h.ServeHTTP(httptest.NewRecorder(), routeRequest(key, listBody))
	h.ServeHTTP(httptest.NewRecorder(), routeRequest(key, callBody("a")))
	if up.lists.Load() != 1 {
		t.Fatalf("same session refetched the listing (%d lists)", up.lists.Load())
	}
	h.ServeHTTP(httptest.NewRecorder(), routeRequest(other, callBody("a")))
	if up.lists.Load() != 2 {
		t.Fatalf("another session reused the first session's listing (%d lists)", up.lists.Load())
	}
}

func TestMCPRouteCatalog_ListingCacheExpiresAfter300s(t *testing.T) {
	a := namedTool("a")
	up := newListingUpstream(t, a)
	h, _, key := catalogHandler(t, catalogFor(up.srv.URL, approvedTools(t, a)))
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }

	h.ServeHTTP(httptest.NewRecorder(), routeRequest(key, callBody("a")))
	now = now.Add(300 * time.Second)
	h.ServeHTTP(httptest.NewRecorder(), routeRequest(key, callBody("a")))
	if up.lists.Load() != 1 {
		t.Fatalf("listing refetched within 300 s (%d lists)", up.lists.Load())
	}
	now = now.Add(time.Second)
	h.ServeHTTP(httptest.NewRecorder(), routeRequest(key, callBody("a")))
	if up.lists.Load() != 2 {
		t.Fatalf("listing not refetched after 300 s (%d lists)", up.lists.Load())
	}
}

func TestMCPRouteCatalog_NewApprovalLiftsTheDriftBlock(t *testing.T) {
	a, b := namedTool("a"), namedTool("b")
	up := newListingUpstream(t, a, b)
	cat := catalogFor(up.srv.URL, approvedTools(t, a))
	h, _, key := catalogHandler(t, cat)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, listBody))
	assertNoTools(t, w)

	cat.setApproval("test-slug", approvedTools(t, a, b), "bundle-2")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, listBody))
	if got := listNames(t, w); len(got) != 2 {
		t.Fatalf("tools = %v after a new approval, want [a b]", got)
	}
}

func TestMCPRouteCatalog_BundleChangeInvalidatesTheCache(t *testing.T) {
	a := namedTool("a")
	up := newListingUpstream(t, a)
	cat := catalogFor(up.srv.URL, approvedTools(t, a))
	h, _, key := catalogHandler(t, cat)

	h.ServeHTTP(httptest.NewRecorder(), routeRequest(key, callBody("a")))
	cat.mu.Lock()
	cat.digest = "bundle-2"
	cat.mu.Unlock()
	h.ServeHTTP(httptest.NewRecorder(), routeRequest(key, callBody("a")))

	if up.lists.Load() != 2 {
		t.Fatalf("listing not reverified after the bundle changed (%d lists)", up.lists.Load())
	}
}

func TestMCPRouteCatalog_NilCatalogFindsNoConnector(t *testing.T) {
	reg, key := testKey(t)
	h := NewHandler(Config{KeyRegistry: reg, Authorizer: fakeAuthorizer{}})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callBody("a")))

	assertDenied(t, w, -31403, "connector_not_found")
}

func TestMCPRouteUpstream_AcceptsJSONAndEventStream(t *testing.T) {
	a := namedTool("a")
	up := newListingUpstream(t, a)
	h, _, key := catalogHandler(t, catalogFor(up.srv.URL, approvedTools(t, a)))

	h.ServeHTTP(httptest.NewRecorder(), routeRequest(key, listBody))

	up.mu.Lock()
	defer up.mu.Unlock()
	if len(up.seen) == 0 {
		t.Fatal("upstream saw no request")
	}
	accept := up.seen[0].Get("Accept")
	if !strings.Contains(accept, "application/json") || !strings.Contains(accept, "text/event-stream") {
		t.Fatalf("Accept = %q, want both application/json and text/event-stream (Streamable HTTP)", accept)
	}
}

func TestMCPRouteEgress_DialsOnlyApprovedMCPHosts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	addr := ln.Addr().String()
	dialWith := func(mcpURL string) error {
		h := NewHandler(Config{Catalog: catalogFor(mcpURL, nil)})
		h.dialCtl = func(string, string, syscall.RawConn) error { return nil }
		conn, err := h.client.Transport.(*http.Transport).DialContext(context.Background(), "tcp", addr)
		if err == nil {
			conn.Close()
		}
		return err
	}

	if err := dialWith("https://" + addr + "/mcp"); err != nil {
		t.Fatalf("dial of an approved mcp host failed: %v", err)
	}
	if err := dialWith("https://mcp.grafana.example/mcp"); err == nil {
		t.Fatalf("dial of %s succeeded; only hosts of approved mcp urls may be dialed", addr)
	}
}

func TestDialControl_BlocksCGNATAndMetadata(t *testing.T) {
	for addr, blocked := range map[string]bool{
		"100.64.0.1:443":              true,
		"100.100.100.100:443":         true, // tailnet MagicDNS
		"100.127.255.254:443":         true,
		"[::ffff:100.64.0.1]:443":     true,
		"169.254.169.254:80":          true,
		"[::ffff:169.254.169.254]:80": true,
		"[fd00:ec2::254]:80":          true,
		"100.128.0.1:443":             false,
		"100.63.255.255:443":          false,
	} {
		err := defaultDialControl("tcp", addr, nil)
		if blocked && err == nil {
			t.Errorf("dialControl(%q) = nil, want blocked", addr)
		}
		if !blocked && err != nil {
			t.Errorf("dialControl(%q) = %v, want allowed", addr, err)
		}
	}
}
