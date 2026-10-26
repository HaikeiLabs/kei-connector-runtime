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
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/invoke"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/session"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
	"github.com/santhosh-tekuri/jsonschema/v6"
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
	manifest := `{"schema":"kei.tool-manifest/v3","tools":[{"name":"demo.read","service":"demo","source":"demo","operation_class":"read","route":{"harness_executor":{"executor":"demo","registration":"demo.read"}}}]}`
	catalogCalls := 0
	catalog := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		catalogCalls++
		if r.Method != http.MethodPut || r.URL.Path != "/api/v1/runtime/tools" {
			t.Errorf("catalog request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+policyTestToken {
			t.Errorf("catalog authorization = %q", got)
		}
		w.Header().Set("X-Kei-Tool-Manifest-Schema", keiruntime.ToolManifestSchemaV3)
		w.Header().Set("X-Kei-Supported-Tool-Manifest-Schemas", keiruntime.ToolManifestSchemaV3)
		w.Header().Set("Content-Type", "application/json")
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
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/tools:register", strings.NewReader(`{"schema":"kei.tool-manifest/v3","tools":[]}`)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing runtime token status = %d, want 401: %s", rec.Code, rec.Body.String())
	}
}

func TestSocketToolRegistrationRejectsInvalidAndEmptyManifests(t *testing.T) {
	for name, body := range map[string]string{
		"empty tools":        `{"schema":"kei.tool-manifest/v3","tools":[]}`,
		"unsupported schema": `{"schema":"kei.tool-manifest/v99","tools":[]}`,
		"invalid definition": `{"schema":"kei.tool-manifest/v3","tools":[{"name":"bad name"}]}`,
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
	req := httptest.NewRequest(http.MethodPost, "/v1/tools:register", strings.NewReader(`{"schema":"kei.tool-manifest/v3","tools":[{"name":"demo.read","service":"demo","source":"demo","operation_class":"read","route":{"harness_executor":{"executor":"demo","registration":"demo.read"}}}]}`))
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

func principalBundle(t *testing.T, agentID, principalID string, expires time.Time) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "pkg", "policybundle", "testdata", "catalog-v2-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	doc["issued_at"], doc["not_after"] = now.Format(time.RFC3339Nano), now.Add(12*time.Hour).Format(time.RFC3339Nano)
	doc["identities"] = []any{map[string]any{
		"subject_type": "service_principal", "service_principal_id": principalID,
		"service_principal_name": "kei-bug-intake",
		"agent_id":               agentID, "groups": []string{"bug-intake"},
		"subject_token": "principal-subject-token", "expire_time": expires.Format(time.RFC3339Nano),
	}}
	audience := doc["audience"].(map[string]any)
	audience["installation_id"], audience["org_id"], audience["workspace_id"] = "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001"
	set := doc["policy_set"].(map[string]any)
	set["org_id"], set["workspace_id"] = "org-fixture-0001", "ws-fixture-0001"
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func principalSessionHandler(t *testing.T, bundle []byte, agentID string, emit keiruntime.EmitAuditFunc) (*keiruntime.LocalPDP, http.Handler) {
	t.Helper()
	validator := subjectV2SchemaValidator(t)
	policybundle.SetV2SchemaValidator(validator)
	t.Cleanup(func() { policybundle.SetV2SchemaValidator(validator) })
	dir := t.TempDir()
	activateBundle(t, dir, bundle)
	l := keiruntime.NewLocalPDP(connectorruntime.Config{RuntimeToken: policyTestToken, RuntimeControlPlaneURL: "https://kei.example", RuntimeStateDir: dir}, emit)
	l.SetIdentity(&keiruntime.Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001"), AgentID: agentID})
	return l, sessionHandler(t, l)
}

func TestSocketSessionStartAsNamedBoundServicePrincipal(t *testing.T) {
	const agentID, principalID = "20000000-0000-0000-0000-000000000006", "sp-bug-intake"
	l, h := principalSessionHandler(t, principalBundle(t, agentID, principalID, time.Now().Add(time.Hour)), agentID, nil)
	rec := putSession(t, h, `{"schema":"kei.session/v2","service_principal_name":"kei-bug-intake"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("start: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		SessionID          string `json:"session_id"`
		ServicePrincipalID string `json:"service_principal_id"`
		SubjectType        string `json:"subject_type"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.ServicePrincipalID != principalID || response.SubjectType != "service_principal" {
		t.Fatalf("principal response = %+v", response)
	}
	if sub, ok := l.Sessions.Get(response.SessionID); !ok || sub.UserID != principalID || sub.Token != "principal-subject-token" {
		t.Fatalf("principal session subject = %+v, live=%t", sub, ok)
	}
}

func TestSocketSessionStartAsBoundServicePrincipal(t *testing.T) {
	const agentID, principalID = "20000000-0000-0000-0000-000000000006", "sp-bug-intake"
	l, h := principalSessionHandler(t, principalBundle(t, agentID, principalID, time.Now().Add(time.Hour)), agentID, nil)
	rec := putSession(t, h, `{"schema":"kei.session/v2","service_principal_id":"sp-bug-intake"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("start: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		SessionID          string `json:"session_id"`
		UserID             string `json:"user_id"`
		SubjectType        string `json:"subject_type"`
		ServicePrincipalID string `json:"service_principal_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.UserID != "" || response.SubjectType != "service_principal" || response.ServicePrincipalID != principalID {
		t.Fatalf("principal response exposes the wrong subject type: %+v", response)
	}
	sub, ok := l.Sessions.Get(response.SessionID)
	if !ok || sub.SubjectKind != "service_principal" || sub.UserID != principalID || strings.Join(sub.Groups, ",") != "bug-intake" || sub.Token != "principal-subject-token" {
		t.Fatalf("principal session subject = %+v, live=%t", sub, ok)
	}
}

func TestSocketSessionNameSelectorRejectsAmbiguousBundleName(t *testing.T) {
	const agentID = "20000000-0000-0000-0000-000000000006"
	raw := principalBundle(t, agentID, "sp-bug-intake", time.Now().Add(time.Hour))
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	identities := doc["identities"].([]any)
	duplicate := make(map[string]any)
	for key, value := range identities[0].(map[string]any) {
		duplicate[key] = value
	}
	duplicate["service_principal_id"] = "sp-bug-intake-duplicate"
	doc["identities"] = append(identities, duplicate)
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	_, h := principalSessionHandler(t, raw, agentID, nil)
	if rec := putSession(t, h, `{"schema":"kei.session/v2","service_principal_name":"kei-bug-intake"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("ambiguous name status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSocketSessionPrincipalSelectorRejectsUnboundAndCallerFields(t *testing.T) {
	const agentID = "20000000-0000-0000-0000-000000000006"
	for _, tc := range []struct {
		name, agent, body string
		expiry            time.Time
	}{
		{"wrong agent", "other-agent", `{"schema":"kei.session/v2","service_principal_id":"sp-bug-intake"}`, time.Now().Add(time.Hour)},
		{"name wrong agent", "other-agent", `{"schema":"kei.session/v2","service_principal_name":"kei-bug-intake"}`, time.Now().Add(time.Hour)},
		{"expired disabled identity", agentID, `{"schema":"kei.session/v2","service_principal_id":"sp-bug-intake"}`, time.Now().Add(-time.Hour)},
		{"name expired identity", agentID, `{"schema":"kei.session/v2","service_principal_name":"kei-bug-intake"}`, time.Now().Add(-time.Hour)},
		{"caller groups", agentID, `{"schema":"kei.session/v2","service_principal_id":"sp-bug-intake","groups":["admin"]}`, time.Now().Add(time.Hour)},
		{"caller agent", agentID, `{"schema":"kei.session/v2","service_principal_id":"sp-bug-intake","agent_id":"other-agent"}`, time.Now().Add(time.Hour)},
		{"caller user", agentID, `{"schema":"kei.session/v2","service_principal_id":"sp-bug-intake","user_id":"user-admin"}`, time.Now().Add(time.Hour)},
		{"caller status", agentID, `{"schema":"kei.session/v2","service_principal_id":"sp-bug-intake","status":"linked"}`, time.Now().Add(time.Hour)},
		{"caller token", agentID, `{"schema":"kei.session/v2","service_principal_id":"sp-bug-intake","subject_token":"forged"}`, time.Now().Add(time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, h := principalSessionHandler(t, principalBundle(t, tc.agent, "sp-bug-intake", tc.expiry), agentID, nil)
			rec := putSession(t, h, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
	_, h := principalSessionHandler(t, principalBundle(t, agentID, "different-principal", time.Now().Add(time.Hour)), agentID, nil)
	if rec := putSession(t, h, `{"schema":"kei.session/v2","service_principal_id":"sp-bug-intake"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing principal status=%d", rec.Code)
	}
	if rec := putSession(t, h, `{"schema":"kei.session/v2","service_principal_id":"sp-bug-intake","service_principal_name":"kei-bug-intake"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("both selectors status=%d", rec.Code)
	}
	if rec := putSession(t, h, `{"schema":"kei.session/v2","service_principal_id":""}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty selector status=%d", rec.Code)
	}
	if rec := putSession(t, h, `{"schema":"kei.session/v2","service_principal_name":"unknown"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown name status=%d", rec.Code)
	}
}

func TestSocketSessionPrincipalAuditUsesTypedSubject(t *testing.T) {
	const agentID = "20000000-0000-0000-0000-000000000006"
	var event json.RawMessage
	_, h := principalSessionHandler(t, principalBundle(t, agentID, "sp-bug-intake", time.Now().Add(time.Hour)), agentID, func(raw json.RawMessage) { event = append(event[:0], raw...) })
	start := putSession(t, h, `{"schema":"kei.session/v2","service_principal_id":"sp-bug-intake"}`)
	if start.Code != http.StatusCreated {
		t.Fatalf("start: %d %s", start.Code, start.Body.String())
	}
	var started struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(start.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	body := `{"schema":"kei.authorize-request/v1","tool":"harness.open_file","framework":"codex"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(body))
	req.Header.Set(session.Header, started.SessionID)
	h.ServeHTTP(rec, req)
	var audit struct {
		InvokingSubject string `json:"invoking_subject"`
	}
	if err := json.Unmarshal(event, &audit); err != nil {
		t.Fatal(err)
	}
	if audit.InvokingSubject != "service_principal:sp-bug-intake" {
		t.Fatalf("invoking_subject=%q event=%s", audit.InvokingSubject, event)
	}
}

func TestSocketAuthorizeServicePrincipalNoLongerBoundDeniesSubjectUnlinked(t *testing.T) {
	const agentID, principalID = "20000000-0000-0000-0000-000000000006", "sp-bug-intake"
	validator := subjectV2SchemaValidator(t)
	policybundle.SetV2SchemaValidator(validator)
	t.Cleanup(func() { policybundle.SetV2SchemaValidator(validator) })
	dir := t.TempDir()
	activateBundle(t, dir, principalBundle(t, agentID, principalID, time.Now().Add(time.Hour)))
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken: policyTestToken, RuntimeControlPlaneURL: "https://kei.example", RuntimeStateDir: dir,
	}, nil)
	t.Cleanup(l.Close)
	l.SetIdentity(&keiruntime.Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001"), AgentID: agentID})
	h := sessionHandler(t, l)
	started := putSession(t, h, `{"schema":"kei.session/v2","service_principal_id":"sp-bug-intake"}`)
	if started.Code != http.StatusCreated {
		t.Fatalf("start: status=%d body=%s", started.Code, started.Body.String())
	}
	var sessionResponse struct {
		ID string `json:"session_id"`
	}
	if err := json.Unmarshal(started.Body.Bytes(), &sessionResponse); err != nil {
		t.Fatal(err)
	}

	updated := principalBundle(t, agentID, "sp-replacement", time.Now().Add(time.Hour))
	var bundle map[string]any
	if err := json.Unmarshal(updated, &bundle); err != nil {
		t.Fatal(err)
	}
	bundle["bundle_version"], bundle["policy_revision"] = float64(4), float64(8)
	updated, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	activateBundle(t, dir, updated)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(`{"schema":"kei.authorize-request/v1","tool":"harness.open_file"}`))
	req.Header.Set(session.Header, sessionResponse.ID)
	h.ServeHTTP(rec, req)
	var decision struct {
		Decision   string `json:"decision"`
		ReasonCode string `json:"reason_code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &decision); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || decision.Decision != "deny" || decision.ReasonCode != "subject_unlinked" {
		t.Fatalf("authorize status=%d decision=%+v body=%s; want 200 deny/subject_unlinked", rec.Code, decision, rec.Body.String())
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
	raw, err := os.ReadFile(filepath.Join("..", "pkg", "policybundle", "testdata", "catalog-v2-bundle.json"))
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
		AgentID:     "agent-fixture-0001",
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
		AgentID:     "agent-fixture-0001",
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
		AgentID:     "agent-fixture-0001",
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

// TestAuthorizeSubjectIsSessionUser verifies that every authorize decision
// uses the session (signed-in) user as the subject, never the agent_id from
// the request. HAI-603 invariant.
func TestAuthorizeSubjectIsSessionUser(t *testing.T) {
	now := time.Now().UTC()
	raw, err := os.ReadFile(filepath.Join("..", "pkg", "policybundle", "testdata", "catalog-v2-bundle.json"))
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
	identity["source"], identity["external_id"] = "discord", "ext-alice"
	identity["user_id"] = "user-alice"
	set := bundle["policy_set"].(map[string]any)
	set["org_id"], set["workspace_id"] = "org-fixture-0001", "ws-fixture-0001"
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

	// Start a session as user-alice.
	putRec := putSession(t, h, `{"schema":"kei.session/v1","source":"discord","external_id":"ext-alice"}`)
	if putRec.Code != http.StatusNoContent {
		t.Fatalf("start session: status=%d body=%s", putRec.Code, putRec.Body.String())
	}

	// Send an authorize request with a DIFFERENT agent_id. The subject
	// must still resolve to the session user, not the request's agent_id,
	// and the authorization AgentID must use the trusted default, not the
	// caller-supplied value.
	body := `{"schema":"kei.authorize-request/v1","tool":"web_search","agent_id":"attacker-agent","on_behalf_of":"user:trigger"}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(body)))

	var response struct {
		Decision string `json:"decision"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	// Verify the audit event: InvokingSubject must be the session user,
	// never the attacker-supplied agent_id.
	var audit struct {
		InvokingSubject string `json:"invoking_subject"`
		AgentID         string `json:"agent_id"`
		OnBehalfOf      string `json:"on_behalf_of"`
	}
	if err := json.Unmarshal(auditEvent, &audit); err != nil {
		t.Fatal(err)
	}
	if audit.InvokingSubject != "user:user-alice" {
		t.Fatalf("InvokingSubject=%q, want %q (typed session user, not request agent_id)", audit.InvokingSubject, "user:user-alice")
	}
	if audit.AgentID != "trusted-default" {
		t.Fatalf("AgentID=%q, want %q (trusted default agent, not request agent_id)", audit.AgentID, "trusted-default")
	}
	if audit.OnBehalfOf != "user:trigger" {
		t.Fatalf("OnBehalfOf=%q, want harness attribution %q", audit.OnBehalfOf, "user:trigger")
	}
}

// TestAuthorizeDefaultEvaluatePathResolvesAgentFromTrustedIdentity verifies
// that the default Evaluate path uses the runtime identity's trusted agent
// for authorization, sets auditTrustedAgent, and denies agent_not_assigned
// when no agent is assigned to the identity.
func TestAuthorizeDefaultEvaluatePathResolvesAgentFromTrustedIdentity(t *testing.T) {
	now := time.Now().UTC()
	raw, err := os.ReadFile(filepath.Join("..", "pkg", "policybundle", "testdata", "catalog-v2-bundle.json"))
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
	identity["source"], identity["external_id"] = "discord", "ext-alice"
	identity["user_id"] = "user-alice"
	set := bundle["policy_set"].(map[string]any)
	set["org_id"], set["workspace_id"] = "org-fixture-0001", "ws-fixture-0001"
	raw, err = json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("no trusted agent denies with agent_not_assigned", func(t *testing.T) {
		dir := t.TempDir()
		activateBundle(t, dir, raw)
		l := keiruntime.NewLocalPDP(connectorruntime.Config{
			RuntimeToken: policyTestToken, RuntimeControlPlaneURL: "https://kei.example", RuntimeStateDir: dir,
		}, nil)
		// No AgentID assigned to the identity.
		l.SetIdentity(&keiruntime.Identity{
			ID: "inst-fixture-0001", OrgID: "org-fixture-0001",
			WorkspaceID: strPtr("ws-fixture-0001"),
		})
		h := l.NewHandler(http.NotFoundHandler(), func() error { return nil }, func(*http.Request) bool { return true })
		putRec := putSession(t, h, `{"schema":"kei.session/v1","source":"discord","external_id":"ext-alice"}`)
		if putRec.Code != http.StatusNoContent {
			t.Fatalf("start session: status=%d body=%s", putRec.Code, putRec.Body.String())
		}
		// web_search is a v1 bundled tool (not a harness tool) that falls
		// through to the default Evaluate path.
		body := `{"schema":"kei.authorize-request/v1","tool":"web_search","agent_id":"some-agent"}`
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(body)))
		var response struct {
			Decision   string `json:"decision"`
			ReasonCode string `json:"reason_code"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if rec.Code != http.StatusOK || response.Decision != "deny" || response.ReasonCode != "agent_not_assigned" {
			t.Fatalf("status=%d response=%+v", rec.Code, response)
		}
	})

	t.Run("trusted agent is used for audit", func(t *testing.T) {
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
		putRec := putSession(t, h, `{"schema":"kei.session/v1","source":"discord","external_id":"ext-alice"}`)
		if putRec.Code != http.StatusNoContent {
			t.Fatalf("start session: status=%d body=%s", putRec.Code, putRec.Body.String())
		}
		// Send request with a DIFFERENT agent_id; audit must show the trusted one.
		body := `{"schema":"kei.authorize-request/v1","tool":"web_search","agent_id":"attacker-agent"}`
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(body)))
		var audit struct {
			AgentID string `json:"agent_id"`
		}
		if err := json.Unmarshal(auditEvent, &audit); err != nil {
			t.Fatal(err)
		}
		if audit.AgentID != "trusted-default" {
			t.Fatalf("audit AgentID=%q, want %q (trusted default agent)", audit.AgentID, "trusted-default")
		}
	})
}

// subjectTestAgent is the one installation agent every HAI-603 path decides
// for. The two sessions below differ only in their signed-in user.
const subjectTestAgent = "agent-fixture-0001"

// subjectSessionIdentities are the two bundle identities: user-alice is in
// group members (permitted tool:x), user-bob is not.
func subjectSessionIdentities() []any {
	return []any{
		map[string]any{"source": "discord", "external_id": "ext-alice", "user_id": "user-alice", "status": "linked", "groups": []string{"members"}},
		map[string]any{"source": "discord", "external_id": "ext-bob", "user_id": "user-bob", "status": "linked", "groups": []string{}},
	}
}

// subjectV2Bundle registers one harness-executed tool (permitted to group
// members) and one MCP tool (permitted to group members) for the one agent.
func subjectV2Bundle(t *testing.T) []byte {
	t.Helper()
	now := time.Now().UTC()
	scope := map[string]any{"org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "agent_id": subjectTestAgent}
	raw, err := json.Marshal(map[string]any{
		"schema": "kei.policy-bundle/v2", "bundle_id": "bundle-v2-subject", "bundle_version": 43, "policy_revision": 8, "issuer": policybundle.Issuer,
		"audience":  map[string]any{"installation_id": "inst-fixture-0001", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001"},
		"issued_at": now.Format(time.RFC3339Nano), "not_after": now.Add(12 * time.Hour).Format(time.RFC3339Nano),
		"refresh": map[string]any{"poll_interval_seconds": 60, "stale_after_seconds": 300}, "subject_resolution": map[string]any{"mode": "bundle", "max_cache_seconds": 60},
		"policy_set": map[string]any{
			"schema": "kei.policy-set/v2", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "match_semantics": "kei.match/v2",
			"evaluation": map[string]any{"precedence": []string{"priority_desc", "deny_before_permit", "policy_id_asc"}, "checks": "per_capability_first_match_and", "default": "deny"},
			"tools": []any{map[string]any{
				"name": "discord.web_search", "source": "discord", "operation_class": "read",
				"route": map[string]any{"harness_executor": map[string]any{"executor": "discord", "registration": "web_search"}},
			}},
			"checks": []any{},
			"tool_policies": []any{map[string]any{
				"policy_id": "p-harness-members", "name": "members web search", "effect": "permit", "priority": 10,
				"scope": scope, "selector": map[string]any{"source_principal": "group:members", "source": "discord", "tool": "discord.web_search"},
			}},
			"harness_match_semantics": "kei.harness-match/v1",
			"harness_policies": []any{map[string]any{
				"policy_id": "p-mcp-members", "name": "members slack", "src_pattern": "group:members", "dst_pattern": "mcp:slack.list_channels", "action": "permit", "priority": 10, "scope": scope,
			}},
		},
		"agent_connector_bindings": []any{},
		"identities":               subjectSessionIdentities(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// subjectV1ConnectorBundle registers one connector capability, permitted to
// group members for the one agent. ConnectorGrant's legacy connector decision
// is evaluated by the v1 policy walk.
func subjectV1ConnectorBundle(t *testing.T) []byte {
	t.Helper()
	now := time.Now().UTC()
	raw, err := json.Marshal(map[string]any{
		"schema": "kei.policy-bundle/v1", "bundle_id": "bundle-v1-subject", "bundle_version": 44, "policy_revision": 9, "issuer": "kei-policy-catalog",
		"audience":  map[string]any{"installation_id": "inst-fixture-0001", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001"},
		"issued_at": now.Format(time.RFC3339), "not_after": now.Add(12 * time.Hour).Format(time.RFC3339),
		"refresh": map[string]any{"poll_interval_seconds": 60, "stale_after_seconds": 300}, "subject_resolution": map[string]any{"mode": "bundle", "max_cache_seconds": 0},
		"policy_set": map[string]any{
			"schema": "kei.policy-set/v1", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "match_semantics": "kei.match/v1",
			"evaluation": map[string]any{"order": "array_order_first_match", "default": "deny"},
			"groups":     []any{},
			"tools": []any{map[string]any{
				"name": "demo.read", "service": "demo", "action": "tool:demo.read", "connector_id": "conn-fixture-0001", "capability": "repository.read",
			}},
			"connectors": []any{map[string]any{
				"id": "conn-fixture-0001", "provider": "demo", "capabilities": []any{map[string]any{"name": "repository.read", "mutating": false}},
			}},
			"agents": []any{map[string]any{"id": subjectTestAgent, "is_default": true}},
			"policies": []any{map[string]any{
				"id": "p-conn-members", "name": "members read", "src_pattern": "group:members", "dst_pattern": "capability:repository.read",
				"action": "permit", "priority": 50, "enabled": true, "approval_required": false,
				"scope": map[string]any{"org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "agent_id": subjectTestAgent},
			}},
		},
		"agent_connector_bindings": []any{map[string]any{"agent_id": subjectTestAgent, "connector_id": "conn-fixture-0001", "capabilities": []string{"repository.read"}}},
		"identities":               subjectSessionIdentities(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// subjectPathDecision is one authorize path's answer for one session.
type subjectPathDecision struct {
	allow   bool
	subject string
}

// TestAuthorizePathsDecideForSessionUserNotAgent is the HAI-603 regression
// table: one agent, two named sessions. user-alice is permitted by a group
// policy, user-bob is not. Every path must permit alice and deny bob for the
// same agent and tool, which only holds while the subject is the session user.
func TestAuthorizePathsDecideForSessionUserNotAgent(t *testing.T) {
	policybundle.SetV2SchemaValidator(subjectV2SchemaValidator(t))
	t.Cleanup(func() { policybundle.SetV2SchemaValidator(nil) })

	paths := []struct {
		name   string
		bundle func(*testing.T) []byte
		decide func(*testing.T, *keiruntime.LocalPDP, http.Handler, string) subjectPathDecision
	}{
		{"authorize v2 harness tool", subjectV2Bundle, decideViaAuthorizeHarnessTool},
		{"mcp route tools/call", subjectV2Bundle, decideViaMCPTool},
		{"connector grant", subjectV1ConnectorBundle, decideViaConnectorGrant},
	}
	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			l, h := subjectRuntime(t, path.bundle(t))
			alice := startSubjectSession(t, h, "ext-alice")
			bob := startSubjectSession(t, h, "ext-bob")

			gotAlice := path.decide(t, l, h, alice)
			gotBob := path.decide(t, l, h, bob)
			if !gotAlice.allow {
				t.Fatalf("user-alice (group members) denied on %s", path.name)
			}
			if gotBob.allow {
				t.Fatalf("user-bob (no group) allowed on %s: the decision used the agent, not the session user", path.name)
			}
			if gotAlice.subject != "" && gotAlice.subject != "user-alice" {
				t.Fatalf("alice decision subject = %q", gotAlice.subject)
			}
			if gotBob.subject != "" && gotBob.subject != "user-bob" {
				t.Fatalf("bob decision subject = %q", gotBob.subject)
			}
		})
	}
}

func decideViaAuthorizeHarnessTool(t *testing.T, _ *keiruntime.LocalPDP, h http.Handler, sessionID string) subjectPathDecision {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(`{"schema":"kei.authorize-request/v1","tool":"discord.web_search","framework":"discord"}`))
	session.SetHeader(req, sessionID)
	h.ServeHTTP(rec, req)
	var response struct {
		Decision string `json:"decision"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("authorize status=%d body=%s", rec.Code, rec.Body.String())
	}
	return subjectPathDecision{allow: response.Decision == "permit"}
}

func decideViaMCPTool(t *testing.T, l *keiruntime.LocalPDP, _ http.Handler, sessionID string) subjectPathDecision {
	t.Helper()
	d, err := l.AuthorizeMCPTool(context.Background(), sessionID, "slack", "list_channels", subjectTestAgent, "claude_code")
	if err != nil {
		t.Fatal(err)
	}
	return subjectPathDecision{allow: d.Allow}
}

func decideViaConnectorGrant(t *testing.T, l *keiruntime.LocalPDP, _ http.Handler, sessionID string) subjectPathDecision {
	t.Helper()
	grant, err := l.ConnectorGrant(context.Background(), invoke.DaemonCall{Session: sessionID, ConnectorID: "conn-fixture-0001", Capability: "repository.read"})
	if err != nil {
		t.Fatal(err)
	}
	return subjectPathDecision{allow: grant.Allow, subject: grant.Subject}
}

// subjectRuntime builds a LocalPDP whose one trusted agent is subjectTestAgent
// and activates bundle, then returns the handler the paths are served through.
func subjectRuntime(t *testing.T, bundle []byte) (*keiruntime.LocalPDP, http.Handler) {
	t.Helper()
	dir := t.TempDir()
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken: policyTestToken, RuntimeControlPlaneURL: "https://kei.example", RuntimeStateDir: dir,
	}, nil)
	l.SetIdentity(&keiruntime.Identity{
		ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001"), AgentID: subjectTestAgent,
	})
	store, err := policybundle.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(bundle, "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	return l, l.NewHandler(http.NotFoundHandler(), func() error { return nil }, func(*http.Request) bool { return true })
}

func startSubjectSession(t *testing.T, h http.Handler, externalID string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/v1/session", strings.NewReader(`{"schema":"kei.session/v2","source":"discord","external_id":"`+externalID+`"}`)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("start session %s: status=%d body=%s", externalID, rec.Code, rec.Body.String())
	}
	var response struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.SessionID == "" {
		t.Fatalf("start session %s: no session id", externalID)
	}
	return response.SessionID
}

// subjectV2SchemaValidator loads the closed v2 schemas so the fixture bundles
// above are validated exactly as production bundles are.
func subjectV2SchemaValidator(t *testing.T) func([]byte) error {
	t.Helper()
	load := func(name string) any {
		b, err := os.ReadFile(filepath.Join("..", "docs", "contracts", name))
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource("https://schemas.haikeilabs.com/kei/policy-set-v2.schema.json", load("policy-set-v2.schema.json")); err != nil {
		t.Fatal(err)
	}
	if err := compiler.AddResource("https://schemas.haikeilabs.com/kei/policy-bundle-v2.schema.json", load("policy-bundle-v2.schema.json")); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("https://schemas.haikeilabs.com/kei/policy-bundle-v2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return func(raw []byte) error {
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			return err
		}
		return schema.Validate(doc)
	}
}
