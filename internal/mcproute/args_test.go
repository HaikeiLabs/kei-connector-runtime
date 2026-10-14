package mcproute

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// primeSchemas injects a verified listing whose tools carry the given
// inputSchemas, as a prior verified tools/list would.
func primeSchemas(t *testing.T, h *Handler, slug string, schemas map[string]string) {
	t.Helper()
	tools := make([]json.RawMessage, 0, len(schemas))
	for name, schema := range schemas {
		b, err := json.Marshal(map[string]any{"name": name, "description": name, "inputSchema": json.RawMessage(schema)})
		if err != nil {
			t.Fatal(err)
		}
		tools = append(tools, b)
	}
	listing, err := newVerifiedListing("sha256:test", tools)
	if err != nil {
		t.Fatal(err)
	}
	primeListing(t, h, slug, listing)
}

const querySchema = `{"type":"object","properties":{"query":{"type":"string"}},"required":["query"],"additionalProperties":false}`

// argsHandler builds a handler whose "search" tool has schema, with a
// recording authorizer and a counting upstream.
func argsHandler(t *testing.T, schema string) (*Handler, string, *[]Decision, func() int64) {
	t.Helper()
	reg, key := testKey(t)
	upstream, hits := countingUpstream(t, okResult)
	var seen []Decision
	h := newHandler(testConfig{KeyRegistry: reg, Authorizer: recordingAuthorizer{&seen}, Upstreams: map[string]UpstreamConfig{
		"test-slug": {URL: upstream.URL, ApprovedToolsHash: "sha256:test"},
	}})
	primeSchemas(t, h, "test-slug", map[string]string{"search": schema})
	return h, key, &seen, hits.Load
}

func callSearch(arguments string) string {
	if arguments == "" {
		return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search"}}`
	}
	return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":` + arguments + `}}`
}

func TestMCPRouteArgs_SchemaViolationDeniedBeforePolicy(t *testing.T) {
	h, key, seen, hits := argsHandler(t, querySchema)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callSearch(`{"query":5}`)))

	assertDenied(t, w, -31400, "invalid_arguments")
	if len(*seen) != 0 {
		t.Fatalf("policy was evaluated %d times; invalid arguments must deny before policy", len(*seen))
	}
	if hits() != 0 {
		t.Fatalf("upstream received %d requests, want 0", hits())
	}
}

func TestMCPRouteArgs_ValidArgumentsForwarded(t *testing.T) {
	h, key, _, hits := argsHandler(t, querySchema)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callSearch(`{"query":"latency"}`)))

	if hits() != 1 {
		t.Fatalf("upstream received %d requests, want 1; body %s", hits(), w.Body.Bytes())
	}
}

func TestMCPRouteArgs_MissingArgumentsValidatedAsEmptyObject(t *testing.T) {
	h, key, _, hits := argsHandler(t, querySchema)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callSearch("")))

	assertDenied(t, w, -31400, "invalid_arguments")
	if hits() != 0 {
		t.Fatalf("upstream received %d requests, want 0", hits())
	}
}

func TestMCPRouteArgs_NonObjectArgumentsDenied(t *testing.T) {
	h, key, _, _ := argsHandler(t, `{}`)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callSearch(`"just a string"`)))

	assertDenied(t, w, -31400, "invalid_arguments")
}

func TestMCPRouteArgs_Over256KiBDenied(t *testing.T) {
	h, key, _, hits := argsHandler(t, `{"type":"object"}`)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callSearch(`{"q":"`+strings.Repeat("a", 256<<10)+`"}`)))

	assertDenied(t, w, -31400, "invalid_arguments")
	if hits() != 0 {
		t.Fatalf("upstream received %d requests, want 0", hits())
	}
}

func nested(levels int) string {
	return strings.Repeat(`{"a":`, levels-1) + `{}` + strings.Repeat(`}`, levels-1)
}

func TestMCPRouteArgs_NestingLimit(t *testing.T) {
	h, key, _, hits := argsHandler(t, `{"type":"object"}`)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callSearch(nested(32))))
	if hits() != 1 {
		t.Fatalf("32 levels: upstream received %d requests, want 1; body %s", hits(), w.Body.Bytes())
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callSearch(nested(33))))
	assertDenied(t, w, -31400, "invalid_arguments")
	if hits() != 1 {
		t.Fatalf("33 levels reached the upstream")
	}
}

func TestMCPRouteArgs_DuplicateKeysDenied(t *testing.T) {
	// The route and the upstream could read different values for a
	// duplicated key, so validation would not cover what is forwarded. The
	// last value ("ok") is valid; the first (7) is not.
	h, key, _, hits := argsHandler(t, querySchema)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callSearch(`{"query":7,"query":"ok"}`)))

	assertDenied(t, w, -31400, "invalid_arguments")
	if hits() != 0 {
		t.Fatalf("upstream received %d requests, want 0", hits())
	}
}

func TestMCPRouteArgs_SchemaNeverLoadsExternalReferences(t *testing.T) {
	// An approved schema that points at a file on the daemon host must not be
	// resolved: the reference fails closed instead of reading the file.
	permissive := filepath.Join(t.TempDir(), "permissive.json")
	if err := os.WriteFile(permissive, []byte(`{"type":"object"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h, key, _, hits := argsHandler(t, `{"$ref":"file://`+filepath.ToSlash(permissive)+`"}`)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callSearch(`{"query":"x"}`)))

	assertDenied(t, w, -31400, "invalid_arguments")
	if hits() != 0 {
		t.Fatalf("upstream received %d requests, want 0", hits())
	}
}

func TestMCPRouteArgs_Draft2020ByDefault(t *testing.T) {
	// prefixItems exists only in JSON Schema 2020-12.
	h, key, _, hits := argsHandler(t, `{"type":"object","properties":{"pair":{"type":"array","prefixItems":[{"type":"string"}]}}}`)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callSearch(`{"pair":[1]}`)))

	assertDenied(t, w, -31400, "invalid_arguments")
	if hits() != 0 {
		t.Fatalf("upstream received %d requests, want 0", hits())
	}
}

func TestMCPRouteArgs_ExplicitDraftHonoured(t *testing.T) {
	// Under draft-07 an array-valued items is a tuple of positional schemas.
	h, key, _, hits := argsHandler(t, `{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"pair":{"type":"array","items":[{"type":"string"}]}}}`)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callSearch(`{"pair":[1]}`)))

	assertDenied(t, w, -31400, "invalid_arguments")
	if hits() != 0 {
		t.Fatalf("upstream received %d requests, want 0", hits())
	}
}
