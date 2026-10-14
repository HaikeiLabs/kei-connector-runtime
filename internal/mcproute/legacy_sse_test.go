package mcproute

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

// ADR-036 §4.2: a connector with transport "sse" speaks the deprecated
// HTTP+SSE transport (MCP 2024-11-05) upstream. The route opens the event
// stream, takes the POST endpoint from its "endpoint" event (same origin
// only), initializes, sends the request and reads the matching response
// from the stream. The harness side is unchanged.

// legacyServer is a 2024-11-05 HTTP+SSE MCP server: GET /sse opens a
// session's event stream, POST /messages?session=<n> takes that session's
// messages and answers on its stream.
type legacyServer struct {
	srv *httptest.Server

	mu       sync.Mutex
	tools    []map[string]any
	auth     []string      // Authorization of every request
	headers  []http.Header // every request's headers
	methods  []string      // methods POSTed, in order
	sessions map[string]*legacySession
	next     int
	// endpoint, when set, is sent instead of "/messages?session=<n>".
	endpoint string
	// noEndpoint closes the stream without an endpoint event.
	noEndpoint bool
	// padding is the number of 64 KiB notifications sent before each response.
	padding int
	// callText, when set, is the text of the tools/call result.
	callText string
	// override, when set, answers every POST.
	override func(sess *legacySession, w http.ResponseWriter)
}

type legacySession struct {
	out         chan []byte
	initialized bool
}

func newLegacyServer(t *testing.T, tools ...map[string]any) *legacyServer {
	t.Helper()
	s := &legacyServer{tools: tools, sessions: map[string]*legacySession{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /sse", s.stream)
	mux.HandleFunc("POST /messages", s.message)
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

func (s *legacyServer) record(r *http.Request, method string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auth = append(s.auth, r.Header.Get("Authorization"))
	s.headers = append(s.headers, r.Header.Clone())
	if method != "" {
		s.methods = append(s.methods, method)
	}
}

func (s *legacyServer) stream(w http.ResponseWriter, r *http.Request) {
	s.record(r, "")
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	flusher := w.(http.Flusher)
	s.mu.Lock()
	s.next++
	id := fmt.Sprint(s.next)
	sess := &legacySession{out: make(chan []byte, 512)}
	s.sessions[id] = sess
	endpoint, none := s.endpoint, s.noEndpoint
	s.mu.Unlock()
	if none {
		return
	}
	if endpoint == "" {
		endpoint = "/messages?session=" + id
	}
	fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", endpoint)
	flusher.Flush()
	for {
		select {
		case msg := <-sess.out:
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", msg)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (s *legacyServer) message(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	s.record(r, req.Method)
	s.mu.Lock()
	sess := s.sessions[r.URL.Query().Get("session")]
	tools, padding, override, callText := s.tools, s.padding, s.override, s.callText
	s.mu.Unlock()
	if sess == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if override != nil {
		override(sess, w)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	reply := func(result string) {
		for i := 0; i < padding; i++ {
			sess.out <- []byte(`{"jsonrpc":"2.0","method":"notifications/message","params":{"data":"` + strings.Repeat("p", 64<<10) + `"}}`)
		}
		sess.out <- []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,%s}`, req.ID, result))
	}
	switch req.Method {
	case "initialize":
		reply(`"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"legacy","version":"1"}}`)
	case "notifications/initialized":
		sess.initialized = true
	case "tools/list":
		if !sess.initialized {
			reply(`"error":{"code":-32002,"message":"not initialized"}`)
			return
		}
		list, _ := json.Marshal(tools)
		reply(`"result":{"tools":` + string(list) + `}`)
	case "tools/call":
		if callText == "" {
			callText = "legacy ok"
		}
		reply(`"result":{"content":[{"type":"text","text":"` + callText + `"}]}`)
	}
}

func legacyRig(t *testing.T, s *legacyServer) (*Handler, string) {
	t.Helper()
	cat := catalogFor(s.srv.URL+"/sse", approvedTools(t, s.tools...))
	cat.connectors[0].MCP.Transport = "sse"
	h, _, key := catalogHandler(t, cat)
	return h, key
}

func TestMCPRouteLegacySSE_ListAndCall(t *testing.T) {
	s := newLegacyServer(t, namedTool("a"))
	h, key := legacyRig(t, s)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, listBody))
	if got := listNames(t, w); len(got) != 1 || got[0] != "a" {
		t.Fatalf("tools/list over HTTP+SSE = %v, want [a]; body %s", got, w.Body.Bytes())
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callBody("a")))
	if !strings.Contains(w.Body.String(), "legacy ok") || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("tools/call over HTTP+SSE = %s (%s)", w.Body.Bytes(), w.Header().Get("Content-Type"))
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	want := []string{"initialize", "notifications/initialized", "tools/list", "initialize", "notifications/initialized", "tools/call"}
	if strings.Join(s.methods, ",") != strings.Join(want, ",") {
		t.Fatalf("upstream saw %v, want %v", s.methods, want)
	}
	for i, a := range s.auth {
		if a != "Bearer ct_test" {
			t.Fatalf("request %d Authorization = %q, want the connector credential on the stream and every POST", i, a)
		}
	}
}

func TestMCPRouteLegacySSE_EndpointOnAnotherOriginIsRefused(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the route posted to another origin: %s %s", r.Method, r.URL)
	}))
	defer other.Close()
	for _, endpoint := range []string{other.URL + "/messages", "//evil.example/messages", "https://evil.example/messages"} {
		s := newLegacyServer(t, namedTool("a"))
		s.endpoint = endpoint
		h, key := legacyRig(t, s)

		w := httptest.NewRecorder()
		h.ServeHTTP(w, routeRequest(key, callBody("a")))

		assertDenied(t, w, -31502, "upstream_protocol_error")
		if len(s.methods) != 0 {
			t.Fatalf("endpoint %q: messages were posted: %v", endpoint, s.methods)
		}
	}
}

func TestMCPRouteLegacySSE_StreamWithoutEndpoint(t *testing.T) {
	s := newLegacyServer(t, namedTool("a"))
	s.noEndpoint = true
	h, key := legacyRig(t, s)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callBody("a")))

	assertDenied(t, w, -31502, "upstream_protocol_error")
}

func TestMCPRouteLegacySSE_StreamIsCappedAt4MiB(t *testing.T) {
	s := newLegacyServer(t, namedTool("a"))
	h, key := legacyRig(t, s)
	h.ServeHTTP(httptest.NewRecorder(), routeRequest(key, listBody)) // verify the listing first
	s.mu.Lock()
	s.padding = 70 // 70 x 64 KiB of notifications before the response
	s.mu.Unlock()

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callBody("a")))

	assertDenied(t, w, -31502, "response_too_large")
}

func TestMCPRouteLegacySSE_Upstream401RejectsTheCredential(t *testing.T) {
	s := newLegacyServer(t, namedTool("a"))
	cat := catalogFor(s.srv.URL+"/denied", approvedTools(t, namedTool("a")))
	cat.connectors[0].MCP.Transport = "sse"
	s.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	h, _, key := catalogHandler(t, cat)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callBody("a")))

	assertDenied(t, w, -31424, "credential_rejected")
}

func TestMCPRouteLegacySSE_FailedInitializeIsAProtocolError(t *testing.T) {
	s := newLegacyServer(t, namedTool("a"))
	h, key := legacyRig(t, s)
	s.override = func(sess *legacySession, w http.ResponseWriter) {
		w.WriteHeader(http.StatusAccepted)
		sess.out <- []byte(`{"jsonrpc":"2.0","id":"kei-initialize","error":{"code":-32603,"message":"boom"}}`)
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callBody("a")))

	assertDenied(t, w, -31502, "upstream_protocol_error")
}

// The released credential echoed in an HTTP+SSE response is dropped, as on
// Streamable HTTP (#197). catalogHandler's credential is "ct_test".
func TestMCPRouteLegacySSE_CredentialEchoIsDropped(t *testing.T) {
	s := newLegacyServer(t, namedTool("a"))
	h, key := legacyRig(t, s)
	h.ServeHTTP(httptest.NewRecorder(), routeRequest(key, listBody))
	s.mu.Lock()
	s.callText = "leaked ct_test"
	s.mu.Unlock()

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callBody("a")))

	assertDenied(t, w, -31502, "credential_echo")
	if strings.Contains(w.Body.String(), "leaked") {
		t.Fatalf("the echoing response reached the harness: %s", w.Body.Bytes())
	}
}

// A secret_ref connector over HTTP+SSE sends its credential_fields headers on
// the stream GET and on every POST (#200), and no Authorization header.
func TestMCPRouteLegacySSE_SecretRefHeadersOnEveryRequest(t *testing.T) {
	s := newLegacyServer(t, namedTool("a"))
	cat := catalogFor(s.srv.URL+"/sse", approvedTools(t, namedTool("a")))
	cat.connectors[0].MCP.Transport = "sse"
	cat.connectors[0].MCP.AuthMethod = "secret_ref"
	cat.connectors[0].MCP.CredentialFields = []policybundle.MCPCredentialField{{Field: "api_key", Header: "DD-API-KEY"}}
	reg, key := testKey(t)
	h := NewHandler(Config{KeyRegistry: reg, Authorizer: fakeAuthorizer{}, Catalog: cat, Secrets: &fakeSecretFields{values: map[string]string{"api_key": apiKeyValue}}})
	h.checkSSRF = noSSRFCheck
	h.dialCtl = noDialCheck

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callBody("a")))
	if !strings.Contains(w.Body.String(), "legacy ok") {
		t.Fatalf("call over HTTP+SSE with secret_ref = %s", w.Body.Bytes())
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.headers) < 4 {
		t.Fatalf("upstream saw %d requests, want the stream and its posts", len(s.headers))
	}
	for i, hdr := range s.headers {
		if hdr.Get("DD-API-KEY") != apiKeyValue || hdr.Get("Authorization") != "" {
			t.Fatalf("request %d: DD-API-KEY %q Authorization %q", i, hdr.Get("DD-API-KEY"), hdr.Get("Authorization"))
		}
	}
}
