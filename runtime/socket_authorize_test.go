package runtime_test

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	connectorruntime "github.com/HaikeiLabs/kei-connector-runtime"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

// fakeKeychain implements keiruntime.SessionKeychain for testing.
type fakeKeychain struct {
	token  string
	userID string
	err    error
}

func (k *fakeKeychain) Token() (string, error)                             { return k.token, k.err }
func (k *fakeKeychain) Verify(_ context.Context, _ string) (string, error) { return k.userID, k.err }

// bundleWithIdentities builds a policy-bundle payload with mode=bundle and the
// given identities. The bundle is valid for 12 hours from now.
func bundleWithIdentities(t *testing.T, ids []policybundle.Identity) []byte {
	t.Helper()
	now := time.Now().UTC()
	idJSON, err := json.Marshal(ids)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(fmt.Sprintf(`{
		"schema":"kei.policy-bundle/v1",
		"bundle_id":"test-bundle",
		"bundle_version":1,
		"policy_revision":1,
		"issuer":"kei-policy-catalog",
		"audience":{"installation_id":"inst-fixture-0001","org_id":"org-fixture-0001","workspace_id":"ws-fixture-0001"},
		"issued_at":"%s","not_after":"%s",
		"refresh":{"poll_interval_seconds":60,"stale_after_seconds":300},
		"subject_resolution":{"mode":"bundle","max_cache_seconds":0},
		"policy_set":{"schema":"kei.policy-set/v1","org_id":"org-fixture-0001","workspace_id":"ws-fixture-0001","match_semantics":"kei.match/v1","evaluation":{"order":"array_order_first_match","default":"deny"},"groups":[],"agents":[{"id":"a1","is_default":true}],"tools":[{"name":"web_search","service":"","action":"tool:web_search"}],"policies":[],"connectors":[]},
		"agent_connector_bindings":[],
		"identities":%s
	}`, now.Format(time.RFC3339), now.Add(12*time.Hour).Format(time.RFC3339), string(idJSON)))
}

// activateBundle opens (or creates) a store at dir, activates the given bundle,
// and returns the store. It does NOT override the schema validator.
func activateBundle(t *testing.T, dir string, bundle []byte) *policybundle.Store {
	t.Helper()
	store, err := policybundle.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(bundle, "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	return store
}

func TestSocketSessionGetReturnsSubjectMinimalResponse(t *testing.T) {
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           policyTestToken,
		RuntimeControlPlaneURL: "https://kei.example",
	}, nil)
	_ = l.Sessions.Start(pdp.Subject{UserID: "user-abc", Email: "user@test", Status: pdp.StatusLinked, Enrollment: json.RawMessage(`"https://claim.url"`)})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	checkConfig := func() error { return nil }
	checkAuth := func(r *http.Request) bool { return true }
	handler := l.NewHandler(next, checkConfig, checkAuth)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/session", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var keys struct {
		Schema     string `json:"schema"`
		UserID     string `json:"user_id"`
		Status     string `json:"status"`
		Email      string `json:"email,omitempty"`
		Enrollment any    `json:"enrollment,omitempty"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &keys); err != nil {
		t.Fatal(err)
	}
	if keys.Schema != "kei.session/v1" || keys.UserID != "user-abc" || keys.Status != "linked" {
		t.Fatalf("response %+v", keys)
	}
	if keys.Email != "" {
		t.Fatal("email leaked in GET /v1/session response")
	}
	if keys.Enrollment != nil {
		t.Fatal("enrollment leaked in GET /v1/session response")
	}
}

func TestSocketToolRegistrationRoundTrip(t *testing.T) {
	manifest := `{"schema":"kei.tool-manifest/v2","tools":[{"name":"demo.read","source":"demo","required_capabilities":["demo.read"],"resource_types":[{"type":"item"}],"operation_class":"read"}]}`
	catalogCalls := 0
	catalog := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		catalogCalls++
		if r.Method != http.MethodPut || r.URL.Path != "/api/v1/runtime/tools" {
			t.Errorf("catalog request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+policyTestToken {
			t.Errorf("catalog authorization = %q", got)
		}
		w.Header().Set("X-Kei-Tool-Manifest-Schema", keiruntime.ToolManifestSchemaV2)
		_, _ = w.Write([]byte(`{"added":1,"updated":2,"removed":3,"unchanged":4}`))
	}))
	defer catalog.Close()

	manifestPath := filepath.Join(t.TempDir(), "tools.json")
	before, err := os.ReadFile(manifestPath)
	if !os.IsNotExist(err) {
		t.Fatalf("manifest fixture should start absent, read err = %v", err)
	}
	l := keiruntime.NewLocalPDP(connectorruntime.Config{RuntimeToken: policyTestToken, RuntimeControlPlaneURL: catalog.URL}, nil)
	h := l.NewHandler(http.NotFoundHandler(), func() error { return nil }, func(r *http.Request) bool {
		return r.Header.Get("Authorization") == "Bearer "+policyTestToken
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/tools:register", strings.NewReader(manifest))
	req.Header.Set("Authorization", "Bearer "+policyTestToken)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("registration status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var counts keiruntime.ToolSyncResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &counts); err != nil {
		t.Fatal(err)
	}
	if counts != (keiruntime.ToolSyncResponse{Added: 1, Updated: 2, Removed: 3, Unchanged: 4}) {
		t.Fatalf("sync counts = %+v", counts)
	}
	if catalogCalls != 1 {
		t.Fatalf("catalog calls = %d, want 1", catalogCalls)
	}
	after, err := os.ReadFile(manifestPath)
	if !os.IsNotExist(err) || len(before) != 0 || len(after) != 0 {
		t.Fatalf("socket registration touched manifest file: read err = %v", err)
	}
}

func TestSocketToolRegistrationRejectsMissingRuntimeToken(t *testing.T) {
	l := keiruntime.NewLocalPDP(connectorruntime.Config{RuntimeToken: policyTestToken, RuntimeControlPlaneURL: "https://kei.example"}, nil)
	h := l.NewHandler(http.NotFoundHandler(), func() error { return nil }, func(*http.Request) bool { return false })
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/tools:register", strings.NewReader(`{"schema":"kei.tool-manifest/v2","tools":[]}`)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing runtime token status = %d, want 401: %s", rec.Code, rec.Body.String())
	}
}

func TestSocketToolRegistrationRejectsInvalidAndEmptyManifests(t *testing.T) {
	for name, body := range map[string]string{
		"empty tools":        `{"schema":"kei.tool-manifest/v2","tools":[]}`,
		"unsupported schema": `{"schema":"kei.tool-manifest/v99","tools":[]}`,
		"invalid definition": `{"schema":"kei.tool-manifest/v2","tools":[{"name":"bad name"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			l := keiruntime.NewLocalPDP(connectorruntime.Config{RuntimeToken: policyTestToken, RuntimeControlPlaneURL: "https://kei.example"}, nil)
			h := l.NewHandler(http.NotFoundHandler(), func() error { return nil }, func(*http.Request) bool { return true })
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/tools:register", strings.NewReader(body)))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("invalid manifest status = %d, want 400: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestSocketToolRegistrationSurfacesCatalogBadRequest(t *testing.T) {
	catalog := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"catalog rejected this manifest"}`))
	}))
	defer catalog.Close()
	l := keiruntime.NewLocalPDP(connectorruntime.Config{RuntimeToken: policyTestToken, RuntimeControlPlaneURL: catalog.URL}, nil)
	h := l.NewHandler(http.NotFoundHandler(), func() error { return nil }, func(*http.Request) bool { return true })
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/tools:register", strings.NewReader(`{"schema":"kei.tool-manifest/v2","tools":[{"name":"demo.read","source":"demo","required_capabilities":["demo.read"],"resource_types":[{"type":"item"}],"operation_class":"read"}]}`))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "catalog rejected this manifest") {
		t.Fatalf("catalog error response = %d %s", rec.Code, rec.Body.String())
	}
}

func TestGenericLocalPDPHandlerStillRequiresRuntimeTokenForAuthorize(t *testing.T) {
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           policyTestToken,
		RuntimeControlPlaneURL: "https://kei.example",
	}, nil)
	next := http.NotFoundHandler()
	handler := l.NewHandler(next, func() error { return nil }, func(*http.Request) bool { return false })
	req := httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(`{"schema":"kei.authorize-request/v1","tool":"pi.read"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated authorize on generic handler status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	status := httptest.NewRecorder()
	handler.ServeHTTP(status, httptest.NewRequest(http.MethodGet, "/v1/policy-bundle/status", nil))
	if status.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated bundle status = %d, want %d", status.Code, http.StatusUnauthorized)
	}
}

func TestSocketSessionGetReturns401WithoutRuntimeToken(t *testing.T) {
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           policyTestToken,
		RuntimeControlPlaneURL: "https://kei.example",
	}, nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	checkConfig := func() error { return nil }
	checkAuth := func(r *http.Request) bool { return false }
	handler := l.NewHandler(next, checkConfig, checkAuth)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/session", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSocketSessionGetReturns404WhenNoSession(t *testing.T) {
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           policyTestToken,
		RuntimeControlPlaneURL: "https://kei.example",
	}, nil)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	checkConfig := func() error { return nil }
	checkAuth := func(r *http.Request) bool { return true }
	handler := l.NewHandler(next, checkConfig, checkAuth)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/session", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func sessionHandler(t *testing.T, l *keiruntime.LocalPDP) http.Handler {
	t.Helper()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	checkConfig := func() error { return nil }
	checkAuth := func(r *http.Request) bool { return true }
	return l.NewHandler(next, checkConfig, checkAuth)
}

func putSession(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/v1/session", strings.NewReader(body))
	h.ServeHTTP(rec, req)
	return rec
}

func getSession(t *testing.T, h http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/session", nil)
	h.ServeHTTP(rec, req)
	return rec
}

func TestSocketSessionStartRejectsOldFields(t *testing.T) {
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           policyTestToken,
		RuntimeControlPlaneURL: "https://kei.example",
	}, nil)
	h := sessionHandler(t, l)

	cases := []struct {
		name string
		body string
	}{
		{"user_id", `{"schema":"kei.session/v1","user_id":"u-1","status":"linked"}`},
		{"email", `{"schema":"kei.session/v1","email":"a@b.com","status":"linked"}`},
		{"status", `{"schema":"kei.session/v1","user_id":"u-1","email":"a@b.com","status":"linked"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := putSession(t, h, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
			}
			var out struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			if out.Error.Code != "invalid_session" {
				t.Fatalf("error code = %s, want invalid_session", out.Error.Code)
			}
		})
	}
}

func TestSocketSessionStartRejectsMissingProvider(t *testing.T) {
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           policyTestToken,
		RuntimeControlPlaneURL: "https://kei.example",
	}, nil)
	h := sessionHandler(t, l)

	rec := putSession(t, h, `{"schema":"kei.session/v1"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Error.Code != "invalid_session" {
		t.Fatalf("error code = %s, want invalid_session", out.Error.Code)
	}
}

func TestSocketSessionStartAcceptsCLI(t *testing.T) {
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           policyTestToken,
		RuntimeControlPlaneURL: "https://kei.example",
	}, nil)
	l.SetKeychain(&fakeKeychain{token: "cli-token-abc", userID: "u-cli-user"})
	h := sessionHandler(t, l)

	rec := putSession(t, h, `{"schema":"kei.session/v1","source":"cli"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify the session is linked with the right user.
	gre := getSession(t, h)
	if gre.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", gre.Code, gre.Body.String())
	}
	var keys struct {
		Schema string `json:"schema"`
		UserID string `json:"user_id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(gre.Body.Bytes(), &keys); err != nil {
		t.Fatal(err)
	}
	if keys.UserID != "u-cli-user" || keys.Status != "linked" {
		t.Fatalf("session = %+v", keys)
	}
}

func TestSocketSessionStartCLIWithoutKeychain(t *testing.T) {
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           policyTestToken,
		RuntimeControlPlaneURL: "https://kei.example",
	}, nil)
	// No keychain set.
	h := sessionHandler(t, l)

	rec := putSession(t, h, `{"schema":"kei.session/v1","source":"cli"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSocketSessionStartCLIFailedVerification(t *testing.T) {
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           policyTestToken,
		RuntimeControlPlaneURL: "https://kei.example",
	}, nil)
	l.SetKeychain(&fakeKeychain{token: "bad-token", userID: "", err: fmt.Errorf("expired")})
	h := sessionHandler(t, l)

	rec := putSession(t, h, `{"schema":"kei.session/v1","source":"cli"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSocketSessionStartResolvesLinkedIdentity(t *testing.T) {
	ids := []policybundle.Identity{
		{Source: "discord", ExternalID: "ext-123", UserID: "u-alice", Status: "linked", Groups: []string{"members"}},
	}
	bundle := bundleWithIdentities(t, ids)
	dir := t.TempDir()
	activateBundle(t, dir, bundle)

	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           policyTestToken,
		RuntimeControlPlaneURL: "https://kei.example",
		RuntimeStateDir:        dir,
	}, nil)
	l.SetIdentity(&keiruntime.Identity{
		ID:          "inst-fixture-0001",
		OrgID:       "org-fixture-0001",
		WorkspaceID: strPtr("ws-fixture-0001"),
	})
	h := sessionHandler(t, l)

	rec := putSession(t, h, `{"schema":"kei.session/v1","source":"discord","external_id":"ext-123"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	gre := getSession(t, h)
	if gre.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", gre.Code, gre.Body.String())
	}
	var keys struct {
		Schema string `json:"schema"`
		UserID string `json:"user_id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(gre.Body.Bytes(), &keys); err != nil {
		t.Fatal(err)
	}
	if keys.UserID != "u-alice" || keys.Status != "linked" {
		t.Fatalf("session = %+v", keys)
	}
}

func TestSocketSessionStartResolvesNonLinkedIdentity(t *testing.T) {
	ids := []policybundle.Identity{
		{Source: "discord", ExternalID: "ext-pending", UserID: "u-bob", Status: "pending"},
	}
	bundle := bundleWithIdentities(t, ids)
	dir := t.TempDir()
	activateBundle(t, dir, bundle)

	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           policyTestToken,
		RuntimeControlPlaneURL: "https://kei.example",
		RuntimeStateDir:        dir,
	}, nil)
	l.SetIdentity(&keiruntime.Identity{
		ID:          "inst-fixture-0001",
		OrgID:       "org-fixture-0001",
		WorkspaceID: strPtr("ws-fixture-0001"),
	})
	h := sessionHandler(t, l)

	rec := putSession(t, h, `{"schema":"kei.session/v1","source":"discord","external_id":"ext-pending"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	gre := getSession(t, h)
	if gre.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", gre.Code, gre.Body.String())
	}
	var keys struct {
		Schema string `json:"schema"`
		UserID string `json:"user_id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(gre.Body.Bytes(), &keys); err != nil {
		t.Fatal(err)
	}
	if keys.UserID != "u-bob" || keys.Status != "pending" {
		t.Fatalf("session = %+v", keys)
	}
}

func TestSocketSessionStartResolvesUnknownIdentity(t *testing.T) {
	ids := []policybundle.Identity{
		{Source: "discord", ExternalID: "ext-123", UserID: "u-alice", Status: "linked"},
	}
	bundle := bundleWithIdentities(t, ids)
	dir := t.TempDir()
	activateBundle(t, dir, bundle)

	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           policyTestToken,
		RuntimeControlPlaneURL: "https://kei.example",
		RuntimeStateDir:        dir,
	}, nil)
	l.SetIdentity(&keiruntime.Identity{
		ID:          "inst-fixture-0001",
		OrgID:       "org-fixture-0001",
		WorkspaceID: strPtr("ws-fixture-0001"),
	})
	h := sessionHandler(t, l)

	rec := putSession(t, h, `{"schema":"kei.session/v1","source":"discord","external_id":"ext-unknown"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	gre := getSession(t, h)
	if gre.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", gre.Code, gre.Body.String())
	}
	var keys struct {
		Schema string `json:"schema"`
		UserID string `json:"user_id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(gre.Body.Bytes(), &keys); err != nil {
		t.Fatal(err)
	}
	if keys.Status != "unlinked" {
		t.Fatalf("session = %+v", keys)
	}
}

func TestSocketSessionStartWithoutBundleIsUnlinked(t *testing.T) {
	// No bundle activated. SetIdentity creates an evaluator pointing at an empty store.
	dir := t.TempDir()

	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           policyTestToken,
		RuntimeControlPlaneURL: "https://kei.example",
		RuntimeStateDir:        dir,
	}, nil)
	l.SetIdentity(&keiruntime.Identity{
		ID:          "inst-fixture-0001",
		OrgID:       "org-fixture-0001",
		WorkspaceID: strPtr("ws-fixture-0001"),
	})
	h := sessionHandler(t, l)

	rec := putSession(t, h, `{"schema":"kei.session/v1","source":"discord","external_id":"ext-123"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	gre := getSession(t, h)
	if gre.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", gre.Code, gre.Body.String())
	}
	var keys struct {
		Schema string `json:"schema"`
		UserID string `json:"user_id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(gre.Body.Bytes(), &keys); err != nil {
		t.Fatal(err)
	}
	if keys.Status != "unlinked" {
		t.Fatalf("session = %+v", keys)
	}
}

func TestSocketSessionStartRejectsMissingProviderUserID(t *testing.T) {
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           policyTestToken,
		RuntimeControlPlaneURL: "https://kei.example",
	}, nil)
	h := sessionHandler(t, l)

	rec := putSession(t, h, `{"schema":"kei.session/v1","source":"discord"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSocketSessionStartResolvesExpiredIdentityAsUnlinked(t *testing.T) {
	now := time.Now().UTC()
	ids := []policybundle.Identity{
		{Source: "discord", ExternalID: "ext-expired", UserID: "u-expired", Status: "linked", ExpireTime: now.Add(-1 * time.Hour)},
	}
	bundle := bundleWithIdentities(t, ids)
	dir := t.TempDir()
	activateBundle(t, dir, bundle)

	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           policyTestToken,
		RuntimeControlPlaneURL: "https://kei.example",
		RuntimeStateDir:        dir,
	}, nil)
	l.SetIdentity(&keiruntime.Identity{
		ID:          "inst-fixture-0001",
		OrgID:       "org-fixture-0001",
		WorkspaceID: strPtr("ws-fixture-0001"),
	})
	h := sessionHandler(t, l)

	rec := putSession(t, h, `{"schema":"kei.session/v1","source":"discord","external_id":"ext-expired"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	gre := getSession(t, h)
	if gre.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", gre.Code, gre.Body.String())
	}
	var keys struct {
		Schema string `json:"schema"`
		UserID string `json:"user_id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(gre.Body.Bytes(), &keys); err != nil {
		t.Fatal(err)
	}
	if keys.Status != "unlinked" {
		t.Fatalf("session = %+v", keys)
	}
}

func bundleWithPolicy(t *testing.T, ids []policybundle.Identity, policies string) []byte {
	t.Helper()
	now := time.Now().UTC()
	idJSON, err := json.Marshal(ids)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(fmt.Sprintf(`{
		"schema":"kei.policy-bundle/v1",
		"bundle_id":"test-bundle",
		"bundle_version":1,
		"policy_revision":1,
		"issuer":"kei-policy-catalog",
		"audience":{"installation_id":"inst-fixture-0001","org_id":"org-fixture-0001","workspace_id":"ws-fixture-0001"},
		"issued_at":"%s","not_after":"%s",
		"refresh":{"poll_interval_seconds":60,"stale_after_seconds":300},
		"subject_resolution":{"mode":"bundle","max_cache_seconds":0},
		"policy_set":{"schema":"kei.policy-set/v1","org_id":"org-fixture-0001","workspace_id":"ws-fixture-0001","match_semantics":"kei.match/v1","evaluation":{"order":"array_order_first_match","default":"deny"},"groups":[],"agents":[{"id":"a1","is_default":true}],"tools":[{"name":"web_search","service":"","action":"tool:web_search"}],"policies":%s,"connectors":[]},
		"agent_connector_bindings":[],
		"identities":%s
	}`, now.Format(time.RFC3339), now.Add(12*time.Hour).Format(time.RFC3339), policies, string(idJSON)))
}

func TestPiShellAuthorizeUsesTrustedDefaultAgentNotRequestAgentID(t *testing.T) {
	now := time.Now().UTC()
	raw, err := os.ReadFile(filepath.Join("..", "internal", "policybundle", "testdata", "catalog-v2-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var bundle map[string]any
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatal(err)
	}
	bundle["issued_at"] = now.Format(time.RFC3339Nano)
	bundle["not_after"] = now.Add(12 * time.Hour).Format(time.RFC3339Nano)
	audience := bundle["audience"].(map[string]any)
	audience["installation_id"], audience["org_id"], audience["workspace_id"] = "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001"
	identities := bundle["identities"].([]any)
	identity := identities[0].(map[string]any)
	identity["source"], identity["external_id"] = "discord", "ext-pi"
	set := bundle["policy_set"].(map[string]any)
	set["org_id"], set["workspace_id"] = "org-fixture-0001", "ws-fixture-0001"
	set["harness_policies"] = []any{map[string]any{
		"policy_id": "trusted-agent-policy", "name": "trusted default agent shell",
		"src_pattern": "agent:trusted-default", "dst_pattern": "shell:git status",
		"action": "permit", "priority": 50,
		"scope": map[string]any{"org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "agent_id": "trusted-default"},
	}}
	raw, err = json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	activateBundle(t, dir, raw)
	var auditEvent json.RawMessage
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken: policyTestToken, RuntimeControlPlaneURL: "https://kei.example", RuntimeStateDir: dir,
	}, func(event json.RawMessage) { auditEvent = append(json.RawMessage(nil), event...) })
	l.SetIdentity(&keiruntime.Identity{
		ID: "inst-fixture-0001", OrgID: "org-fixture-0001",
		WorkspaceID: strPtr("ws-fixture-0001"), AgentID: "trusted-default",
	})
	h := l.NewHandler(http.NotFoundHandler(), func() error { return nil }, func(*http.Request) bool { return true })
	putRec := putSession(t, h, `{"schema":"kei.session/v1","source":"discord","external_id":"ext-pi"}`)
	if putRec.Code != http.StatusNoContent {
		t.Fatalf("start session: status=%d body=%s", putRec.Code, putRec.Body.String())
	}
	const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	body := `{"schema":"kei.authorize-request/v1","tool":"pi.bash","agent_id":"attacker-agent","framework":"pi","shell_command":"git status --short","tool_args_digest":"` + digest + `"}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(body)))
	var response struct {
		Decision string `json:"decision"`
		PolicyID string `json:"policy_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || response.Decision != "permit" || response.PolicyID != "trusted-agent-policy" {
		t.Fatalf("request AgentID overrode trusted assignment: status=%d response=%+v body=%s", rec.Code, response, rec.Body.String())
	}
	var audit struct {
		AgentID        string  `json:"agent_id"`
		ToolArgsDigest *string `json:"tool_args_digest"`
	}
	if err := json.Unmarshal(auditEvent, &audit); err != nil {
		t.Fatal(err)
	}
	if audit.AgentID != "trusted-default" || audit.ToolArgsDigest == nil || *audit.ToolArgsDigest != digest || strings.Contains(string(auditEvent), "git status --short") {
		t.Fatalf("audit did not retain trusted agent and digest-only metadata: %s", auditEvent)
	}
}

func TestSocketSessionAuthorizeAfterBundleLinkedSession(t *testing.T) {
	// A user resolved from bundle identities should be authorized for tools
	// permitted by their resolved groups.
	ids := []policybundle.Identity{
		{Source: "discord", ExternalID: "ext-123", UserID: "u-alice", Status: "linked", Groups: []string{"members"}},
	}
	memberPolicy := `[{"id":"p-allow-web-search","name":"allow-web-search","src_pattern":"group:members","dst_pattern":"tool:web_search","action":"permit","priority":50,"enabled":true,"approval_required":false,"scope":{"org_id":"org-fixture-0001","workspace_id":"ws-fixture-0001","agent_id":null}}]`
	bundle := bundleWithPolicy(t, ids, memberPolicy)
	dir := t.TempDir()
	activateBundle(t, dir, bundle)

	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           policyTestToken,
		RuntimeControlPlaneURL: "https://kei.example",
		RuntimeStateDir:        dir,
	}, nil)
	l.SetIdentity(&keiruntime.Identity{
		ID:          "inst-fixture-0001",
		OrgID:       "org-fixture-0001",
		WorkspaceID: strPtr("ws-fixture-0001"),
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	checkConfig := func() error { return nil }
	checkAuth := func(r *http.Request) bool { return true }
	h := l.NewHandler(next, checkConfig, checkAuth)

	// Start session
	putRec := putSession(t, h, `{"schema":"kei.session/v1","source":"discord","external_id":"ext-123"}`)
	if putRec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", putRec.Code, putRec.Body.String())
	}

	// Authorize
	authRec := httptest.NewRecorder()
	authReq := httptest.NewRequest(http.MethodPost, "/v1/authorize",
		strings.NewReader(`{"schema":"kei.authorize-request/v1","tool":"web_search"}`))
	h.ServeHTTP(authRec, authReq)

	if authRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", authRec.Code, authRec.Body.String())
	}
	var out struct {
		Decision string `json:"decision"`
	}
	if err := json.Unmarshal(authRec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Decision != "permit" {
		t.Fatalf("decision = %s, want permit: %s", out.Decision, authRec.Body.String())
	}
}

func TestSocketSessionAuthorizeAfterBundleRevokedSession(t *testing.T) {
	// A revoked identity should deny with reason subject_revoked.
	ids := []policybundle.Identity{
		{Source: "discord", ExternalID: "ext-revoked", UserID: "u-carol", Status: "revoked"},
	}
	bundle := bundleWithIdentities(t, ids)
	dir := t.TempDir()
	activateBundle(t, dir, bundle)

	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           policyTestToken,
		RuntimeControlPlaneURL: "https://kei.example",
		RuntimeStateDir:        dir,
	}, nil)
	l.SetIdentity(&keiruntime.Identity{
		ID:          "inst-fixture-0001",
		OrgID:       "org-fixture-0001",
		WorkspaceID: strPtr("ws-fixture-0001"),
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	checkConfig := func() error { return nil }
	checkAuth := func(r *http.Request) bool { return true }
	h := l.NewHandler(next, checkConfig, checkAuth)

	putRec := putSession(t, h, `{"schema":"kei.session/v1","source":"discord","external_id":"ext-revoked"}`)
	if putRec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", putRec.Code, putRec.Body.String())
	}

	authRec := httptest.NewRecorder()
	authReq := httptest.NewRequest(http.MethodPost, "/v1/authorize",
		strings.NewReader(`{"schema":"kei.authorize-request/v1","tool":"web_search"}`))
	h.ServeHTTP(authRec, authReq)

	if authRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", authRec.Code, authRec.Body.String())
	}
	var out struct {
		Decision   string `json:"decision"`
		ReasonCode string `json:"reason_code"`
	}
	if err := json.Unmarshal(authRec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Decision != "deny" || out.ReasonCode != "subject_revoked" {
		t.Fatalf("decision = %s reason = %s, want deny subject_revoked: %s", out.Decision, out.ReasonCode, authRec.Body.String())
	}
}

func TestSocketSessionAuthorizeAfterUnlinkedSession(t *testing.T) {
	// Unknown identity -> unlinked session -> should deny with subject_unlinked
	ids := []policybundle.Identity{
		{Source: "discord", ExternalID: "ext-123", UserID: "u-alice", Status: "linked", Groups: []string{"members"}},
	}
	bundle := bundleWithIdentities(t, ids)
	dir := t.TempDir()
	activateBundle(t, dir, bundle)

	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           policyTestToken,
		RuntimeControlPlaneURL: "https://kei.example",
		RuntimeStateDir:        dir,
	}, nil)
	l.SetIdentity(&keiruntime.Identity{
		ID:          "inst-fixture-0001",
		OrgID:       "org-fixture-0001",
		WorkspaceID: strPtr("ws-fixture-0001"),
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	checkConfig := func() error { return nil }
	checkAuth := func(r *http.Request) bool { return true }
	h := l.NewHandler(next, checkConfig, checkAuth)

	putRec := putSession(t, h, `{"schema":"kei.session/v1","source":"discord","external_id":"ext-unknown"}`)
	if putRec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", putRec.Code, putRec.Body.String())
	}

	authRec := httptest.NewRecorder()
	authReq := httptest.NewRequest(http.MethodPost, "/v1/authorize",
		strings.NewReader(`{"schema":"kei.authorize-request/v1","tool":"web_search"}`))
	h.ServeHTTP(authRec, authReq)

	if authRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", authRec.Code, authRec.Body.String())
	}
	var out struct {
		Decision   string `json:"decision"`
		ReasonCode string `json:"reason_code"`
	}
	if err := json.Unmarshal(authRec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Decision != "deny" || out.ReasonCode != "subject_unlinked" {
		t.Fatalf("decision = %s reason = %s, want deny subject_unlinked: %s", out.Decision, out.ReasonCode, authRec.Body.String())
	}
}

func TestSocketSessionStartResolvesOpenWebUILinkedIdentity(t *testing.T) {
	ids := []policybundle.Identity{
		{Source: "openwebui", ExternalID: "550e8400-e29b-41d4-a716-446655440000", UserID: "u-owui", Status: "linked", Groups: []string{"members"}},
	}
	bundle := bundleWithIdentities(t, ids)
	dir := t.TempDir()
	activateBundle(t, dir, bundle)

	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           policyTestToken,
		RuntimeControlPlaneURL: "https://kei.example",
		RuntimeStateDir:        dir,
	}, nil)
	l.SetIdentity(&keiruntime.Identity{
		ID:          "inst-fixture-0001",
		OrgID:       "org-fixture-0001",
		WorkspaceID: strPtr("ws-fixture-0001"),
	})
	h := sessionHandler(t, l)

	rec := putSession(t, h, `{"schema":"kei.session/v1","source":"openwebui","external_id":"550e8400-e29b-41d4-a716-446655440000"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	gre := getSession(t, h)
	if gre.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", gre.Code, gre.Body.String())
	}
	var keys struct {
		Schema string `json:"schema"`
		UserID string `json:"user_id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(gre.Body.Bytes(), &keys); err != nil {
		t.Fatal(err)
	}
	if keys.UserID != "u-owui" || keys.Status != "linked" {
		t.Fatalf("session = %+v", keys)
	}
}

func TestSocketSessionStartOpenWebUIUnknownIdentity(t *testing.T) {
	ids := []policybundle.Identity{
		{Source: "openwebui", ExternalID: "550e8400-e29b-41d4-a716-446655440000", UserID: "u-owui", Status: "linked"},
	}
	bundle := bundleWithIdentities(t, ids)
	dir := t.TempDir()
	activateBundle(t, dir, bundle)

	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           policyTestToken,
		RuntimeControlPlaneURL: "https://kei.example",
		RuntimeStateDir:        dir,
	}, nil)
	l.SetIdentity(&keiruntime.Identity{
		ID:          "inst-fixture-0001",
		OrgID:       "org-fixture-0001",
		WorkspaceID: strPtr("ws-fixture-0001"),
	})
	h := sessionHandler(t, l)

	rec := putSession(t, h, `{"schema":"kei.session/v1","source":"openwebui","external_id":"00000000-0000-0000-0000-000000000000"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	gre := getSession(t, h)
	if gre.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", gre.Code, gre.Body.String())
	}
	var keys struct {
		Schema string `json:"schema"`
		UserID string `json:"user_id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(gre.Body.Bytes(), &keys); err != nil {
		t.Fatal(err)
	}
	if keys.Status != "unlinked" {
		t.Fatalf("session = %+v", keys)
	}
}

func TestSocketAuthorizeDeniesBeforeIdentityResolves(t *testing.T) {
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           policyTestToken,
		RuntimeControlPlaneURL: "https://kei.example",
	}, nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	checkConfig := func() error { return nil }
	checkAuth := func(r *http.Request) bool {
		const prefix = "Bearer "
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, prefix) {
			return false
		}
		token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
		return token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(policyTestToken)) == 1
	}
	handler := l.NewHandler(next, checkConfig, checkAuth)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(`{"schema":"kei.authorize-request/v1","tool":"search_wiki"}`))
	req.Header.Set("Authorization", "Bearer "+policyTestToken)
	handler.ServeHTTP(rec, req)
	var out struct {
		Schema      string `json:"schema"`
		Decision    string `json:"decision"`
		ReasonCode  string `json:"reason_code"`
		DenySource  string `json:"deny_source"`
		BundleState string `json:"bundle_state"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || out.Decision != "deny" || out.ReasonCode != "policy_bundle_missing" || out.DenySource != "runtime_state" || out.BundleState != "cold" {
		t.Fatalf("status %d response %+v", rec.Code, out)
	}
}
