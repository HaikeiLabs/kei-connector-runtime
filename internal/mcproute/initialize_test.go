package mcproute

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"testing"
)

// ADR-036 §4.2/§4.5: the route answers initialize itself, speaks protocol
// revisions 2025-06-18, 2025-11-25 and 2026-07-28 to harnesses, advertises
// only {"tools": {"listChanged": false}}, and never mints Mcp-Session-Id.

func initialize(t *testing.T, requested string) (result map[string]any, w *httptest.ResponseRecorder) {
	t.Helper()
	reg, key := testKey(t)
	h := newHandler(testConfig{KeyRegistry: reg})
	params, _ := json.Marshal(map[string]any{"protocolVersion": requested, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "test", "version": "1"}})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":`+string(params)+`}`))
	var resp struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.Result == nil {
		t.Fatalf("initialize answered %s", w.Body.Bytes())
	}
	return resp.Result, w
}

func TestMCPRouteInitialize_AdvertisesTheLatestRevision(t *testing.T) {
	for requested, want := range map[string]string{
		"2026-07-28": "2026-07-28",
		"2025-11-25": "2025-11-25",
		"2025-06-18": "2025-06-18",
		"2024-11-05": "2026-07-28", // unsupported: the route offers its latest
		"2099-01-01": "2026-07-28",
		"":           "2026-07-28",
	} {
		result, w := initialize(t, requested)
		if result["protocolVersion"] != want {
			t.Errorf("requested %q: protocolVersion = %v, want %s", requested, result["protocolVersion"], want)
		}
		if got := w.Header().Get("Mcp-Session-Id"); got != "" {
			t.Errorf("requested %q: the route minted Mcp-Session-Id %q", requested, got)
		}
	}
}

func TestMCPRouteInitialize_AdvertisesOnlyNonChangingTools(t *testing.T) {
	result, _ := initialize(t, "2026-07-28")
	want := map[string]any{"tools": map[string]any{"listChanged": false}}
	if !reflect.DeepEqual(result["capabilities"], want) {
		t.Fatalf("capabilities = %#v, want %#v", result["capabilities"], want)
	}
}
