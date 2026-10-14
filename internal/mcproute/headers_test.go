package mcproute

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ADR-036 §4.2 and §4.5 step 2: an MCP-Protocol-Version the route does not
// speak is 400 UnsupportedProtocolVersionError, and request metadata headers
// that disagree with the body are 400 with JSON-RPC -32020 (HeaderMismatch).
// Neither reaches the upstream server.

func headerRequest(key, body string, headers map[string]string) *http.Request {
	req := routeRequest(key, body)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func assertProtocolError(t *testing.T, w *httptest.ResponseRecorder, code int, message string) {
	t.Helper()
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", w.Code, w.Body.Bytes())
	}
	var resp struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.Error == nil {
		t.Fatalf("not a JSON-RPC error: %s", w.Body.Bytes())
	}
	if resp.Error.Code != code || resp.Error.Message != message {
		t.Fatalf("error = %d %q, want %d %q", resp.Error.Code, resp.Error.Message, code, message)
	}
}

func headerRig(t *testing.T) (*Handler, string, *listingUpstream) {
	t.Helper()
	a := namedTool("a")
	up := newListingUpstream(t, a)
	h, _, key := catalogHandler(t, catalogFor(up.srv.URL, approvedTools(t, a)))
	return h, key, up
}

func TestMCPRouteHeaders_UnsupportedProtocolVersionIs400(t *testing.T) {
	for _, version := range []string{"2025-03-26", "2024-11-05", "2099-01-01", "latest"} {
		h, key, up := headerRig(t)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, headerRequest(key, callBody("a"), map[string]string{"MCP-Protocol-Version": version}))

		assertProtocolError(t, w, -32600, "UnsupportedProtocolVersionError")
		if up.lists.Load()+up.calls.Load() != 0 {
			t.Fatalf("version %q reached the upstream", version)
		}
	}
}

func TestMCPRouteHeaders_SupportedProtocolVersionsPass(t *testing.T) {
	for _, version := range []string{"2025-06-18", "2025-11-25", "2026-07-28"} {
		h, key, up := headerRig(t)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, headerRequest(key, callBody("a"), map[string]string{"MCP-Protocol-Version": version}))
		if w.Code != http.StatusOK || up.calls.Load() != 1 {
			t.Fatalf("version %s: status %d calls %d; body %s", version, w.Code, up.calls.Load(), w.Body.Bytes())
		}
	}
}

func TestMCPRouteHeaders_MismatchIsMinus32020(t *testing.T) {
	initialize := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`
	for name, tc := range map[string]struct {
		body    string
		headers map[string]string
	}{
		"Mcp-Name differs from params.name":    {callBody("a"), map[string]string{"Mcp-Name": "other_tool"}},
		"Mcp-Method differs from method":       {callBody("a"), map[string]string{"Mcp-Method": "tools/list"}},
		"version header differs on initialize": {initialize, map[string]string{"MCP-Protocol-Version": "2025-11-25"}},
		"Mcp-Name on a method without a name":  {listBody, map[string]string{"Mcp-Name": "a"}},
	} {
		t.Run(name, func(t *testing.T) {
			h, key, up := headerRig(t)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, headerRequest(key, tc.body, tc.headers))

			assertProtocolError(t, w, -32020, "HeaderMismatch")
			if up.lists.Load()+up.calls.Load() != 0 {
				t.Fatal("a mismatched request reached the upstream")
			}
		})
	}
}

func TestMCPRouteHeaders_MatchingMetadataPasses(t *testing.T) {
	h, key, up := headerRig(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, headerRequest(key, callBody("a"), map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "a"}))
	if w.Code != http.StatusOK || up.calls.Load() != 1 {
		t.Fatalf("status %d calls %d; body %s", w.Code, up.calls.Load(), w.Body.Bytes())
	}
}

func TestMCPRouteHeaders_AbsentHeadersAreAccepted(t *testing.T) {
	h, key, up := headerRig(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callBody("a")))
	if w.Code != http.StatusOK || up.calls.Load() != 1 {
		t.Fatalf("status %d calls %d", w.Code, up.calls.Load())
	}
}
