package mcproute

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

// rpcError is a decoded JSON-RPC error with the ADR-036 §4.5 error.data.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    *struct {
		Reason     string `json:"reason"`
		DecisionID string `json:"decision_id"`
	} `json:"data"`
}

func decodeRPCError(t *testing.T, body []byte) rpcError {
	t.Helper()
	var resp struct {
		Error *rpcError `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode JSON-RPC response %q: %v", body, err)
	}
	if resp.Error == nil {
		t.Fatalf("expected a JSON-RPC error, got %s", body)
	}
	return *resp.Error
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// assertDenied checks an ADR-036 §4.5 denial: HTTP 200, the code, the
// reason in error.data, and a decision_id.
func assertDenied(t *testing.T, w *httptest.ResponseRecorder, code int, reason string) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (denials are JSON-RPC errors); body %s", w.Code, w.Body.Bytes())
	}
	e := decodeRPCError(t, w.Body.Bytes())
	if e.Code != code {
		t.Fatalf("error code = %d, want %d (%+v)", e.Code, code, e)
	}
	if e.Data == nil || e.Data.Reason != reason {
		t.Fatalf("error.data.reason = %+v, want %q", e.Data, reason)
	}
	if !uuidPattern.MatchString(e.Data.DecisionID) {
		t.Fatalf("error.data.decision_id = %q, want a UUID", e.Data.DecisionID)
	}
}

func routeRequest(key, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/mcp/test-slug", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	req.Host = "127.0.0.1:8086"
	return req
}

const callY = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"Y","arguments":{}}}`

// countingUpstream counts requests and answers each with respond.
func countingUpstream(t *testing.T, respond http.HandlerFunc) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		respond(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func okResult(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`))
}

func TestMCPRoute_RequestOver1MiBRejectedBeforeUpstream(t *testing.T) {
	reg, key := testKey(t)
	upstream, hits := countingUpstream(t, okResult)
	h := newHandler(testConfig{KeyRegistry: reg, Authorizer: fakeAuthorizer{}, Upstreams: map[string]UpstreamConfig{
		"test-slug": {URL: upstream.URL, ApprovedToolsHash: "sha256:dummy"},
	}})
	primeTools(t, h, "test-slug", "Y")

	big := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"Y","arguments":{"q":"` + strings.Repeat("a", 1<<20) + `"}}}`
	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, big))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a request over 1 MiB", w.Code)
	}
	if hits.Load() != 0 {
		t.Fatalf("upstream received %d requests, want 0", hits.Load())
	}
}

func TestMCPRoute_ResponseOver4MiBDropped(t *testing.T) {
	reg, key := testKey(t)
	upstream, _ := countingUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"%s"}]}}`, strings.Repeat("b", 4<<20))
	})
	h := newHandler(testConfig{KeyRegistry: reg, Authorizer: fakeAuthorizer{}, Upstreams: map[string]UpstreamConfig{
		"test-slug": {URL: upstream.URL, ApprovedToolsHash: "sha256:dummy"},
	}})
	primeTools(t, h, "test-slug", "Y")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callY))

	assertDenied(t, w, -31502, "response_too_large")
	if w.Body.Len() > 4096 {
		t.Fatalf("response carries %d bytes of the oversized upstream body", w.Body.Len())
	}
}

func TestMCPRoute_SSEResponseOver4MiBTerminated(t *testing.T) {
	reg, key := testKey(t)
	upstream, _ := countingUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		event := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"pad\":\"" + strings.Repeat("c", 64<<10) + "\"}}\n\n"
		for i := 0; i < 80; i++ { // 80 x 64 KiB > 4 MiB
			w.Write([]byte(event))
		}
	})
	h := newHandler(testConfig{KeyRegistry: reg, Authorizer: fakeAuthorizer{}, Upstreams: map[string]UpstreamConfig{
		"test-slug": {URL: upstream.URL, ApprovedToolsHash: "sha256:dummy"},
	}})
	primeTools(t, h, "test-slug", "Y")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callY))

	out := w.Body.String()
	if len(out) > 4<<20+4096 {
		t.Fatalf("relayed %d bytes, want at most 4 MiB plus the terminating error", len(out))
	}
	if !strings.Contains(out, `"response_too_large"`) {
		t.Fatalf("stream does not end with a response_too_large error; tail %q", out[max(0, len(out)-300):])
	}
}

func TestMCPRoute_UpstreamTimeout(t *testing.T) {
	reg, key := testKey(t)
	release := make(chan struct{})
	upstream, _ := countingUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		case <-time.After(2 * time.Second): // RED without a client timeout fails, never hangs
		}
		okResult(w, r)
	})
	defer close(release)
	h := newHandler(testConfig{KeyRegistry: reg, Authorizer: fakeAuthorizer{}, UpstreamTimeout: 50 * time.Millisecond, Upstreams: map[string]UpstreamConfig{
		"test-slug": {URL: upstream.URL, ApprovedToolsHash: "sha256:dummy"},
	}})
	primeTools(t, h, "test-slug", "Y")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callY))

	assertDenied(t, w, -31502, "upstream_timeout")
}

func TestMCPRoute_UpstreamTimeoutDefaultAndCap(t *testing.T) {
	if got := buildHandler(testConfig{}).client.Timeout; got != 60*time.Second {
		t.Fatalf("default upstream timeout = %v, want 60s", got)
	}
	if got := buildHandler(testConfig{UpstreamTimeout: 10 * time.Minute}).client.Timeout; got != 300*time.Second {
		t.Fatalf("upstream timeout = %v, want it capped at 300s", got)
	}
}

func TestMCPRoute_UpstreamResponseHeadersNotCopied(t *testing.T) {
	reg, key := testKey(t)
	upstream, _ := countingUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "upstream=1")
		w.Header().Set("Mcp-Session-Id", "upstream-session")
		w.Header().Set("X-Upstream-Internal", "leak")
		okResult(w, r)
	})
	h := newHandler(testConfig{KeyRegistry: reg, Authorizer: fakeAuthorizer{}, Upstreams: map[string]UpstreamConfig{
		"test-slug": {URL: upstream.URL, ApprovedToolsHash: "sha256:dummy"},
	}})
	primeTools(t, h, "test-slug", "Y")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callY))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	for _, name := range []string{"Set-Cookie", "Mcp-Session-Id", "X-Upstream-Internal"} {
		if v := w.Header().Get(name); v != "" {
			t.Errorf("upstream header %s = %q reached the harness", name, v)
		}
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
}

func TestMCPRoute_IPv6LoopbackHostAllowed(t *testing.T) {
	reg, key := testKey(t)
	h := newHandler(testConfig{KeyRegistry: reg})
	req := routeRequest(key, `{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	req.Host = "[::1]:8086"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for Host [::1]:8086; body %s", w.Code, w.Body.Bytes())
	}
}

func TestMCPRoute_HostWithoutLoopbackPortForms(t *testing.T) {
	reg, key := testKey(t)
	h := newHandler(testConfig{KeyRegistry: reg})
	for _, host := range []string{"", "127.0.0.1", "[::1]", "::1:8086", "127.0.0.1.evil.com:8086", "localhost.evil.com:8086"} {
		req := routeRequest(key, `{"jsonrpc":"2.0","id":1,"method":"ping"}`)
		req.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("Host %q: status = %d, want 403", host, w.Code)
		}
	}
}

func TestMCPRoute_OriginAndHostCheckedBeforeRouteKey(t *testing.T) {
	reg, _ := testKey(t)
	h := newHandler(testConfig{KeyRegistry: reg})

	withOrigin := routeRequest("", `{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	withOrigin.Header.Set("Origin", "https://evil.example")
	foreignHost := routeRequest("kmr_unknown", `{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	foreignHost.Host = "evil.example:8086"

	for name, req := range map[string]*http.Request{"origin": withOrigin, "host": foreignHost} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s: status = %d, want 403", name, w.Code)
		}
		e := decodeRPCError(t, w.Body.Bytes())
		if e.Message == errAuthFailed || (e.Data != nil && e.Data.Reason == errAuthFailed) {
			t.Fatalf("%s: rejected as %s; Origin and Host must be checked before the route key", name, errAuthFailed)
		}
	}
}

func TestMCPRoute_DenialCodes(t *testing.T) {
	reg, key := testKey(t)
	upstream, hits := countingUpstream(t, okResult)
	cfg := func() testConfig {
		return testConfig{KeyRegistry: reg, Authorizer: fakeAuthorizer{}, Upstreams: map[string]UpstreamConfig{
			"test-slug": {URL: upstream.URL, ApprovedToolsHash: "sha256:dummy"},
		}}
	}
	call := func(tool string) string {
		return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `","arguments":{}}}`
	}
	tests := []struct {
		name   string
		build  func() *Handler
		body   string
		code   int
		reason string
	}{
		{"connector_not_found", func() *Handler {
			c := cfg()
			c.Connectors = []policybundle.Connector{}
			return buildHandler(c)
		}, call("Y"), -31403, "connector_not_found"},
		{"connector_not_bound", func() *Handler {
			c := cfg()
			c.Connectors = []policybundle.Connector{{ID: "conn-1", Kind: "mcp", Slug: "test-slug"}}
			return buildHandler(c)
		}, call("Y"), -31403, "connector_not_bound"},
		{"policy_denied", func() *Handler { h := newHandler(cfg()); primeTools(t, h, "test-slug", "X"); return h }, call("X"), -31403, "mcp_not_authorized"},
		{"mcp_manifest_unapproved", func() *Handler {
			c := cfg()
			c.Upstreams["test-slug"] = UpstreamConfig{URL: upstream.URL}
			return newHandler(c)
		}, call("Y"), -31409, "mcp_manifest_unapproved"},
		{"mcp_manifest_drift", func() *Handler {
			// The session's connector is blocked after drift (§5.3).
			h := newHandler(cfg())
			h.blocked[listingKey{session: "test-session", connector: "conn-test-slug"}] = "sha256:dummy"
			return h
		}, call("Y"), -31409, "mcp_manifest_drift"},
		{"mcp_tool_not_approved", func() *Handler { h := newHandler(cfg()); primeTools(t, h, "test-slug", "Z"); return h }, call("Y"), -31409, "mcp_tool_not_approved"},
		{"upstream_blocked", func() *Handler {
			h := newHandlerSSRF(cfg())
			primeTools(t, h, "test-slug", "Y")
			return h
		}, call("Y"), -31502, "upstream_blocked"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := hits.Load()
			w := httptest.NewRecorder()
			tt.build().ServeHTTP(w, routeRequest(key, tt.body))
			assertDenied(t, w, tt.code, tt.reason)
			if hits.Load() != before {
				t.Fatalf("upstream received a request for a %s denial", tt.reason)
			}
		})
	}
}

func TestMCPRoute_RedirectIsUpstreamProtocolError(t *testing.T) {
	reg, key := testKey(t)
	upstream, _ := countingUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/elsewhere", http.StatusFound)
	})
	h := newHandler(testConfig{KeyRegistry: reg, Authorizer: fakeAuthorizer{}, Upstreams: map[string]UpstreamConfig{
		"test-slug": {URL: upstream.URL, ApprovedToolsHash: "sha256:dummy"},
	}})
	primeTools(t, h, "test-slug", "Y")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callY))

	assertDenied(t, w, -31502, "upstream_protocol_error")
}

func TestMCPRoute_ToolsListDriftReturnsNoTools(t *testing.T) {
	reg, key := testKey(t)
	upstream, _ := countingUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"tools": []any{namedTool("changed")}}})
	})
	h := newHandler(testConfig{KeyRegistry: reg, Authorizer: fakeAuthorizer{}, Upstreams: map[string]UpstreamConfig{
		"test-slug": {URL: upstream.URL, ApprovedToolsHash: hashNamedTools(t, "approved"), ApprovedTools: approvedNamed(t, "approved")},
	}})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (ADR-036 §5.3: lists return no tools on drift)", w.Code)
	}
	var resp struct {
		Result *struct {
			Tools []json.RawMessage `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Result == nil || resp.Result.Tools == nil || len(resp.Result.Tools) != 0 {
		t.Fatalf("want an empty tools list, got %s", w.Body.Bytes())
	}
}

func TestMCPRoute_LogsNeverContainUpstreamURL(t *testing.T) {
	reg, key := testKey(t)
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close() // connection refused: the transport error names the URL
	secretURL := closed.URL + "/mcp/p4th-s3cret?token=q5ery-s3cret"

	var logs bytes.Buffer
	h := newHandler(testConfig{KeyRegistry: reg, Authorizer: fakeAuthorizer{}, Logger: slog.New(slog.NewTextHandler(&logs, nil)), Upstreams: map[string]UpstreamConfig{
		"test-slug": {URL: secretURL, ApprovedToolsHash: "sha256:dummy"},
	}})
	primeTools(t, h, "test-slug", "Y")

	for _, body := range []string{callY, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`} {
		h.ServeHTTP(httptest.NewRecorder(), routeRequest(key, body))
	}

	if logs.Len() == 0 {
		t.Fatal("expected the upstream failure to be logged")
	}
	for _, secret := range []string{"p4th-s3cret", "q5ery-s3cret"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("log contains the upstream URL (%s): %s", secret, logs.String())
		}
	}
}

// assertNoTools checks a tools/list answer with an empty tools array, the
// ADR-036 §5.3 response to drift.
func assertNoTools(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", w.Code, w.Body.Bytes())
	}
	var resp struct {
		Result *struct {
			Tools []json.RawMessage `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Result == nil || resp.Result.Tools == nil || len(resp.Result.Tools) != 0 {
		t.Fatalf("want an empty tools list, got %s", w.Body.Bytes())
	}
}

// recordingAuthorizer permits every call and records the decisions it saw.
type recordingAuthorizer struct{ got *[]Decision }

func (a recordingAuthorizer) Authorize(_ context.Context, d Decision) (Verdict, error) {
	*a.got = append(*a.got, d)
	return Verdict{}, nil
}

func TestMCPRouteCall_SessionFromKeyNotHeader(t *testing.T) {
	reg := NewKeyRegistry()
	key, err := reg.Mint(Session{Subject: "test-session", Agent: "test-agent", HarnessKind: "claude_code", SessionID: "test-session"})
	if err != nil {
		t.Fatal(err)
	}
	upstream, _ := countingUpstream(t, okResult)
	var got []Decision
	h := newHandler(testConfig{KeyRegistry: reg, Authorizer: recordingAuthorizer{&got}, Upstreams: map[string]UpstreamConfig{
		"test-slug": {URL: upstream.URL, ApprovedToolsHash: "sha256:dummy"},
	}})
	primeTools(t, h, "test-slug", "Y")

	req := routeRequest(key, callY)
	req.Header.Set("X-Kei-Session", "session-B")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if len(got) != 1 || got[0].SessionID != "test-session" || got[0].HarnessKind != "claude_code" {
		t.Fatalf("authorizer saw %+v, want the session bound to the route key (test-session)", got)
	}
}
