package mcproute

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/HaikeiLabs/kei-connector-contracts/manifest"
)

// ADR-036 §5.3-§5.4: a listing the route cannot verify is submitted to the
// catalog as a candidate manifest, once per (connector, manifest_hash).

type submission struct {
	connectorID, hash string
	tools             []json.RawMessage
}

type fakeSubmitter struct {
	mu   sync.Mutex
	got  []submission
	errs []error
}

func (f *fakeSubmitter) Submit(_ context.Context, connectorID, hash string, tools []json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, submission{connectorID, hash, tools})
	if len(f.errs) > 0 {
		err := f.errs[0]
		f.errs = f.errs[1:]
		return err
	}
	return nil
}

func (f *fakeSubmitter) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.got)
}

func submitRig(t *testing.T, approved bool, tools ...map[string]any) (*Handler, *KeyRegistry, string, *listingUpstream, *fakeSubmitter) {
	t.Helper()
	up := newListingUpstream(t, tools...)
	var approval []map[string]any
	if approved {
		approval = tools[:1]
	}
	cat := catalogFor(up.srv.URL, nil)
	if approved {
		cat = catalogFor(up.srv.URL, approvedTools(t, approval...))
	}
	h, reg, key := catalogHandler(t, cat)
	sub := &fakeSubmitter{}
	h.config.Submitter = sub
	return h, reg, key, up, sub
}

func observedHash(t *testing.T, tools ...map[string]any) string {
	t.Helper()
	raw := make([]json.RawMessage, len(tools))
	for i, tool := range tools {
		raw[i], _ = json.Marshal(tool)
	}
	h, err := manifest.Hash(raw)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestMCPRouteManifest_DriftSubmitsOneCandidate(t *testing.T) {
	a, b := namedTool("a"), namedTool("b")
	b["title"], b["annotations"] = "B", map[string]any{"readOnlyHint": true}
	h, _, key, _, sub := submitRig(t, true, a, b)

	h.ServeHTTP(httptest.NewRecorder(), routeRequest(key, listBody))
	h.ServeHTTP(httptest.NewRecorder(), routeRequest(key, callBody("a")))
	h.ServeHTTP(httptest.NewRecorder(), routeRequest(key, listBody))
	h.submits.Wait()

	if sub.count() != 1 {
		t.Fatalf("submitted %d candidates, want 1", sub.count())
	}
	got := sub.got[0]
	if got.connectorID != "conn-1" || got.hash != observedHash(t, a, b) {
		t.Fatalf("submitted %s %s, want conn-1 %s", got.connectorID, got.hash, observedHash(t, a, b))
	}
	for _, tool := range got.tools {
		var members map[string]any
		_ = json.Unmarshal(tool, &members)
		if len(members) != 3 || members["name"] == nil || members["inputSchema"] == nil {
			t.Fatalf("submitted tool %s is not a canonical {name, description, inputSchema} object", tool)
		}
	}
}

func TestMCPRouteManifest_UnapprovedListSubmitsTheObservedManifest(t *testing.T) {
	a := namedTool("a")
	h, _, key, up, sub := submitRig(t, false, a)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, listBody))
	assertDenied(t, w, -31409, "mcp_manifest_unapproved")
	h.ServeHTTP(httptest.NewRecorder(), routeRequest(key, callBody("a")))
	h.submits.Wait()

	if sub.count() != 1 || sub.got[0].hash != observedHash(t, a) {
		t.Fatalf("submissions %+v, want one candidate for the observed listing", sub.got)
	}
	if up.calls.Load() != 0 || up.lists.Load() != 1 {
		t.Fatalf("lists %d calls %d: an unapproved connector is only listed, never called", up.lists.Load(), up.calls.Load())
	}
}

func TestMCPRouteManifest_InvalidManifestIsNotSubmitted(t *testing.T) {
	tools := make([]map[string]any, 0, 513)
	for i := 0; i < 513; i++ {
		tools = append(tools, namedTool(fmt.Sprintf("tool_%03d", i)))
	}
	h, _, key, _, sub := submitRig(t, true, tools...)

	h.ServeHTTP(httptest.NewRecorder(), routeRequest(key, listBody))
	h.submits.Wait()

	if sub.count() != 0 {
		t.Fatalf("submitted %d candidates for a manifest the catalog must reject", sub.count())
	}
}

func TestMCPRouteManifest_SubmissionsAreDedupedAcrossSessions(t *testing.T) {
	a, b := namedTool("a"), namedTool("b")
	h, reg, key, _, sub := submitRig(t, true, a, b)
	other, _ := reg.Mint(Session{Subject: "s2", Agent: "test-agent", HarnessKind: "claude_code", SessionID: "session-2"})

	h.ServeHTTP(httptest.NewRecorder(), routeRequest(key, listBody))
	h.ServeHTTP(httptest.NewRecorder(), routeRequest(other, listBody))
	h.submits.Wait()

	if sub.count() != 1 {
		t.Fatalf("submitted %d candidates for one observed manifest, want 1", sub.count())
	}
}

func TestMCPRouteManifest_FailedSubmissionIsRetriedOnTheNextObservation(t *testing.T) {
	a, b := namedTool("a"), namedTool("b")
	h, reg, key, _, sub := submitRig(t, true, a, b)
	sub.errs = []error{errors.New("catalog unavailable")}
	other, _ := reg.Mint(Session{Subject: "s2", Agent: "test-agent", HarnessKind: "claude_code", SessionID: "session-2"})

	h.ServeHTTP(httptest.NewRecorder(), routeRequest(key, listBody))
	h.submits.Wait()
	h.ServeHTTP(httptest.NewRecorder(), routeRequest(other, listBody))
	h.submits.Wait()

	if sub.count() != 2 {
		t.Fatalf("submitted %d times, want a retry after the failed submission", sub.count())
	}
}

const submitToken = "kh_live_runtime_submit_token_488"

func TestCatalogManifestClient_PostsTheCatalogContract(t *testing.T) {
	a := namedTool("a")
	a["title"] = "dropped"
	raw, _ := json.Marshal(a)
	var gotPath, gotAuth, gotType string
	var gotBody map[string]json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth, gotType = r.Method+" "+r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		_ = dec.Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"id":"m-1","status":"candidate"}`)
	}))
	defer srv.Close()
	c := CatalogManifestClient{BaseURL: srv.URL, RuntimeToken: submitToken, Scope: func() (string, string, string) { return "org-1", "ws-1", "inst-1" }}

	hash := observedHash(t, a)
	if err := c.Submit(context.Background(), "conn-1", hash, []json.RawMessage{raw}); err != nil {
		t.Fatal(err)
	}
	if gotPath != "POST /api/v1/organizations/org-1/workspaces/ws-1/data-connectors/conn-1/tool-manifests" {
		t.Fatalf("request = %s", gotPath)
	}
	if gotAuth != "Bearer "+submitToken || gotType != "application/json" {
		t.Fatalf("Authorization %q Content-Type %q", gotAuth, gotType)
	}
	if len(gotBody) != 2 || string(gotBody["manifest_hash"]) != `"`+hash+`"` {
		t.Fatalf("body = %v, want exactly manifest_hash and tools", gotBody)
	}
	var tools []map[string]any
	_ = json.Unmarshal(gotBody["tools"], &tools)
	if len(tools) != 1 || len(tools[0]) != 3 || tools[0]["title"] != nil {
		t.Fatalf("tools = %s, want canonical objects", gotBody["tools"])
	}
	var asRaw []json.RawMessage
	_ = json.Unmarshal(gotBody["tools"], &asRaw)
	if h, _ := manifest.Hash(asRaw); h != hash {
		t.Fatalf("the catalog would recompute %s, want %s", h, hash)
	}
}

func TestCatalogManifestClient_Statuses(t *testing.T) {
	for status, wantErr := range map[int]bool{http.StatusCreated: false, http.StatusOK: false, http.StatusBadRequest: true, http.StatusUnauthorized: true, http.StatusInternalServerError: true} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			io.WriteString(w, `{"error":{"message":"echo `+submitToken+`"}}`)
		}))
		c := CatalogManifestClient{BaseURL: srv.URL, RuntimeToken: submitToken, Scope: func() (string, string, string) { return "o", "w", "i" }}
		raw, _ := json.Marshal(namedTool("a"))
		err := c.Submit(context.Background(), "conn-1", observedHash(t, namedTool("a")), []json.RawMessage{raw})
		srv.Close()
		if (err != nil) != wantErr {
			t.Errorf("status %d: err = %v, want error %v", status, err, wantErr)
		}
		if err != nil && strings.Contains(err.Error(), submitToken) {
			t.Errorf("status %d: error carries the response body or token: %v", status, err)
		}
	}
}

func TestCatalogManifestClient_NoScopeFailsClosed(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	c := CatalogManifestClient{BaseURL: srv.URL, RuntimeToken: submitToken, Scope: func() (string, string, string) { return "", "", "" }}
	raw, _ := json.Marshal(namedTool("a"))

	if err := c.Submit(context.Background(), "conn-1", observedHash(t, namedTool("a")), []json.RawMessage{raw}); err == nil || hits != 0 {
		t.Fatalf("err %v hits %d, want an error and no request before the identity resolves", err, hits)
	}
}

func TestMCPRouteManifest_DuplicateToolNamesAreNotSubmitted(t *testing.T) {
	// The listing is fetched, but it is not a valid manifest (§5.2 rule 6):
	// the catalog would reject it, so it is not submitted.
	a := namedTool("a")
	dup := namedTool("a")
	dup["description"] = "second a"
	h, _, key, _, sub := submitRig(t, true, a, dup)

	h.ServeHTTP(httptest.NewRecorder(), routeRequest(key, listBody))
	h.submits.Wait()

	if sub.count() != 0 {
		t.Fatalf("submitted %d candidates for a manifest with duplicate names", sub.count())
	}
}
