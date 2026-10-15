package invoke

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/crm"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/httpapi"
)

// These tests drive `connector invoke` end to end against fakes: a fake
// catalog behind the real wire client, a fake secret store, host-routed
// provider fixtures, and a captured audit sink. Nothing touches the network
// or a real credential.

const (
	execToken      = "fake-oauth-access-token-0001"
	execTitoToken  = "fake-tito-api-token-000000001"
	execNotionTok  = "fake-notion-integration-token-01"
	execCRMKey     = "fake-crm-connector-key-0000000000000001"
	execTenant     = "11111111-1111-1111-1111-111111111111"
	execWorkspace  = "22222222-2222-2222-2222-222222222222"
	execAgent      = "33333333-3333-3333-3333-333333333333"
	execConnector  = "44444444-4444-4444-4444-444444444444"
	execUser       = "55555555-5555-5555-5555-555555555555"
	execInstall    = "66666666-6666-6666-6666-666666666666"
	execTrace      = "trace-exec-0001"
	execSecretRef  = "kei-prod-connector-44444444"
	execBackend    = "aws-secrets-manager"
	execAssertKID  = "kei-rt-66666666-6666-6666-6666-666666666666-1"
	execAssertRef  = "kei-prod-runtime-assertion-key"
	execCRMBaseURL = "https://crm.example.com"
)

var errBackendDown = errors.New("secret backend unavailable")

type execSecretStore struct {
	mu     sync.Mutex
	values map[string]string // backend + "|" + ref
	gets   int
}

func (s *execSecretStore) Get(_ context.Context, backend, ref string) (*string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gets++
	if backend != execBackend {
		return nil, fmt.Errorf("%w: %q", errBackendDown, backend)
	}
	v, ok := s.values[backend+"|"+ref]
	if !ok {
		return nil, errors.New("secret not found")
	}
	return &v, nil
}

type routeTransport struct {
	mu     sync.Mutex
	routes map[string]http.HandlerFunc
	calls  []*http.Request
}

func (rt *routeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.mu.Lock()
	rt.calls = append(rt.calls, req)
	h, ok := rt.routes[req.URL.Host]
	rt.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no fixture for host %s", req.URL.Host)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec.Result(), nil
}

func (rt *routeTransport) callCount() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return len(rt.calls)
}

type execHarness struct {
	t              *testing.T
	catalogStatus  int
	catalogBody    string
	catalogReqs    []map[string]any
	catalogCalled  int
	controlPlane   string
	store          *execSecretStore
	transport      *routeTransport
	assertionKey   *ecdsa.PrivateKey
	withAssertion  bool
	stdin          string
	now            time.Time
	lastStdout     string
	lastStderr     string
	lastAuditLines []string
}

func newExecHarness(t *testing.T) *execHarness {
	t.Helper()
	return &execHarness{
		t:             t,
		catalogStatus: http.StatusOK,
		controlPlane:  "https://kei.example.com",
		store:         &execSecretStore{values: map[string]string{}},
		transport:     &routeTransport{routes: map[string]http.HandlerFunc{}},
		now:           time.Now().UTC(),
	}
}

// catalog serves every catalog request, whatever the control-plane host.
func (h *execHarness) catalog() http.RoundTripper {
	return roundTripFunc(func(r *http.Request) (*http.Response, error) {
		h.catalogCalled++
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		h.catalogReqs = append(h.catalogReqs, body)
		rec := httptest.NewRecorder()
		rec.WriteHeader(h.catalogStatus)
		_, _ = io.WriteString(rec, h.catalogBody)
		return rec.Result(), nil
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func (h *execHarness) enableAssertionKey() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		h.t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		h.t.Fatal(err)
	}
	h.store.values[execBackend+"|"+execAssertRef] = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	h.assertionKey = key
	h.withAssertion = true
}

func (h *execHarness) run(args ...string) (map[string]any, int) {
	h.t.Helper()
	var stdout, stderr bytes.Buffer
	h.lastAuditLines = nil
	env := Env{
		RuntimeToken:           "kh_live_exec_runtime_token_0001",
		RuntimeControlPlaneURL: h.controlPlane,
		Stdin:                  strings.NewReader(h.stdin),
		Store:                  h.store,
		BackendUnavailable:     func(err error) bool { return errors.Is(err, errBackendDown) },
		Audit: func(record []byte) error {
			h.lastAuditLines = append(h.lastAuditLines, string(record))
			return nil
		},
		CatalogTransport:  h.catalog(),
		ProviderTransport: h.transport,
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		},
		Now: func() time.Time { return h.now },
	}
	if h.withAssertion {
		env.AssertionKey = crm.KeyConfig{Backend: execBackend, Ref: execAssertRef, KID: execAssertKID}
	}
	base := []string{"--connector", execConnector, "--trace-id", execTrace, "--framework", "pde"}
	code := Run(append(base, args...), env, &stdout, &stderr)
	h.lastStdout, h.lastStderr = stdout.String(), stderr.String()
	var out map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		h.t.Fatalf("stdout is not one JSON object: %q (stderr %q)", stdout.String(), stderr.String())
	}
	// Invariants for every outcome: no credential or reference leaks into
	// stdout, stderr, or the audit record.
	for _, secret := range []string{execToken, execTitoToken, execNotionTok, execCRMKey, "BEGIN PRIVATE KEY", execSecretRef} {
		for name, text := range map[string]string{"stdout": h.lastStdout, "stderr": h.lastStderr, "audit": strings.Join(h.lastAuditLines, "\n")} {
			if strings.Contains(text, secret) {
				h.t.Fatalf("%s leaked credential material %q", name, secret)
			}
		}
	}
	return out, code
}

func (h *execHarness) assertDeny(out map[string]any, code int, reasonCode string) {
	h.t.Helper()
	if code != 1 || out["decision"] != "deny" || out["reason_code"] != reasonCode {
		h.t.Fatalf("outcome = exit %d %v, want deny %s (stderr %q)", code, out, reasonCode, h.lastStderr)
	}
	if _, ok := out["result"]; ok {
		h.t.Fatalf("deny carried a result: %v", out)
	}
}

func (h *execHarness) auditRecord() map[string]any {
	h.t.Helper()
	if len(h.lastAuditLines) != 1 {
		h.t.Fatalf("audit lines = %d, want 1: %v", len(h.lastAuditLines), h.lastAuditLines)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(h.lastAuditLines[0]), &rec); err != nil {
		h.t.Fatal(err)
	}
	return rec
}

func envelopeJSON(capability, action, resource, subject string) string {
	return fmt.Sprintf(`{"version":"1.0","minted_by":"kei-control-plane","issued_at":"2026-09-28T12:00:00Z","invocation":{"tenant_id":%q,"workspace_id":%q,"subject":%q,"agent_id":%q,"connector_id":%q,"capability":%q,"action":%q,"resource":%q,"trace_id":%q}}`,
		execTenant, execWorkspace, subject, execAgent, execConnector, capability, action, resource, execTrace)
}

func descriptorJSON(provider, source, model, subject string, capabilities string, extra string) string {
	scopes := []string{"read"}
	if provider == "google_drive" {
		scopes = []string{"https://www.googleapis.com/auth/drive.readonly"}
	} else if provider == "gmail" {
		scopes = []string{"https://www.googleapis.com/auth/gmail.readonly"}
	}
	scopesJSON, _ := json.Marshal(scopes)
	d := fmt.Sprintf(`{"id":%q,"tenant_id":%q,"workspace_id":%q,"name":"conn","provider":%q,"status":"active","credential_source":%q,"credential_ref":%q,"scopes":%s,"resources":["*"],"policy":{"allowed_actions":["read"],"allowed_resources":["*"]},"capabilities":%s,"created_by":%q`,
		execConnector, execTenant, execWorkspace, provider, source, execSecretRef, string(scopesJSON), capabilities, execUser)
	if model != "" {
		d += fmt.Sprintf(`,"account_model":%q`, model)
	}
	if subject != "" {
		d += fmt.Sprintf(`,"subject":%q`, subject)
	}
	if source == "opaque_ref" {
		d += fmt.Sprintf(`,"credential_backend":%q`, execBackend)
	}
	return d + extra + "}"
}

func oauthJSON(expires time.Time) string {
	return fmt.Sprintf(`{"access_token":%q,"token_type":"Bearer","expires_at":%q,"account_email_digest":"hmac-sha256:abc123"}`, execToken, expires.Format(time.RFC3339))
}

func allowJSON(envelope, descriptor, oauth string) string {
	body := fmt.Sprintf(`{"decision":"allow","envelope":%s,"connector":%s,"credential_subject":%q`, envelope, descriptor, execUser)
	if oauth != "" {
		body += `,"oauth":` + oauth
	}
	return body + "}"
}

const gmailCaps = `[{"name":"message.search","action":"read"},{"name":"message.get","action":"read"}]`

func (h *execHarness) gmailPerUserAllow() {
	h.catalogBody = allowJSON(envelopeJSON("message.search", "read", "gmail/messages", execUser),
		descriptorJSON("gmail", "oauth", "per_user", "", gmailCaps, ""), oauthJSON(h.now.Add(time.Minute)))
}

func (h *execHarness) routeGmail() {
	h.transport.routes["gmail.googleapis.com"] = func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+execToken {
			h.t.Errorf("gmail authorization = %q", got)
		}
		switch r.URL.Path {
		case "/gmail/v1/users/me/messages":
			if r.URL.Query().Get("q") != "from:alice" {
				h.t.Errorf("gmail q = %q", r.URL.Query().Get("q"))
			}
			_, _ = io.WriteString(w, `{"messages":[{"id":"m-1","threadId":"th-1"}],"nextPageToken":"p-2"}`)
		case "/gmail/v1/users/me/messages/m-1":
			if f := r.URL.Query().Get("format"); f != "metadata" {
				h.t.Errorf("gmail format = %q, want metadata", f)
			}
			_, _ = io.WriteString(w, `{"id":"m-1","threadId":"th-1","labelIds":["INBOX"],"snippet":"hi bob","internalDate":"1700000000123","payload":{"headers":[{"name":"From","value":"Alice <alice@example.test>"},{"name":"To","value":"bob@example.test"},{"name":"Subject","value":"Hello"}]}}`)
		default:
			http.NotFound(w, r)
		}
	}
}

// PDE's Gmail search: the WhatsApp phone travels to the catalog, which
// resolves the invoking Kei user and returns that user's token; the query stays
// in the runtime and only its digest reaches the catalog.
func TestConnectorInvokeGmailSearchPerUser(t *testing.T) {
	h := newExecHarness(t)
	h.gmailPerUserAllow()
	h.routeGmail()
	out, code := h.run("--capability", "message.search", "--action", "read", "--resource", "gmail/messages",
		"--provider-user", "+15551234567", "--input", `{"query":"from:alice","page_size":5}`)
	if code != 0 || out["decision"] != "allow" {
		t.Fatalf("outcome = %d %v (stderr %q)", code, out, h.lastStderr)
	}
	result := out["result"].(map[string]any)
	msgs := result["messages"].([]any)
	if len(msgs) != 1 || msgs[0].(map[string]any)["subject"] != "Hello" || result["next_page_token"] != "p-2" {
		t.Fatalf("result = %v", result)
	}
	if _, ok := msgs[0].(map[string]any)["body"]; ok {
		t.Fatal("search returned a body")
	}

	req := h.catalogReqs[0]
	if req["provider_user_id"] != "+15551234567" {
		t.Fatalf("provider_user_id = %v", req["provider_user_id"])
	}
	digest, _ := req["input_digest"].(string)
	if !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("input_digest = %q", digest)
	}
	raw, _ := json.Marshal(req)
	if strings.Contains(string(raw), "from:alice") || req["input"] != nil {
		t.Fatalf("catalog request carried the input: %s", raw)
	}

	audit := out["audit"].(map[string]any)
	if audit["input_digest"] != digest || !strings.HasPrefix(audit["result_digest"].(string), "sha256:") {
		t.Fatalf("stdout audit = %v", audit)
	}
	rec := h.auditRecord()
	if rec["decision"] != "allow" || rec["tool_args_digest"] != digest || rec["parent_span"] != execTrace ||
		rec["tool_name"] != "connector:gmail:message.search" || rec["credential_subject"] != execUser ||
		rec["account_email_digest"] != "hmac-sha256:abc123" || rec["account_model"] != "per_user" ||
		rec["provider_status_class"] != "2xx" || rec["org_id"] != execTenant {
		t.Fatalf("audit record = %v", rec)
	}
	if strings.Contains(h.lastAuditLines[0], "from:alice") || strings.Contains(h.lastAuditLines[0], "hi bob") {
		t.Fatal("audit carried input or result content")
	}
}

// The input may also arrive on stdin, which keeps a query out of the process
// list.
func TestConnectorInvokeReadsInputFromStdin(t *testing.T) {
	h := newExecHarness(t)
	h.gmailPerUserAllow()
	h.routeGmail()
	h.stdin = `{"query":"from:alice"}`
	out, code := h.run("--capability", "message.search", "--action", "read", "--resource", "gmail/messages", "--user", execUser, "--input", "-")
	if code != 0 || out["decision"] != "allow" {
		t.Fatalf("outcome = %d %v (stderr %q)", code, out, h.lastStderr)
	}
}

// Tito resolves its API token from the tenant secret store (path 1). The
// value never leaves the runtime.
func TestConnectorInvokeTitoUsesSharedSecret(t *testing.T) {
	h := newExecHarness(t)
	h.store.values[execBackend+"|"+execSecretRef] = execTitoToken
	caps := `[{"name":"event.list","action":"read"}]`
	h.catalogBody = allowJSON(envelopeJSON("event.list", "read", "tito/acme/events", execUser),
		descriptorJSON("tito", "opaque_ref", "", "", caps, `,"config":{"account_slug":"acme"}`), "")
	h.transport.routes["api.tito.io"] = func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Token token="+execTitoToken {
			t.Errorf("tito authorization = %q", got)
		}
		_, _ = io.WriteString(w, `{"events":[{"slug":"conf-2026","title":"Conf 2026","url":"https://ti.to/acme/conf-2026","start_date":"2026-10-01","end_date":"2026-10-02","live":true}],"meta":{"next_page":null}}`)
	}
	out, code := h.run("--capability", "event.list", "--action", "read", "--resource", "tito/acme/events", "--user", execUser, "--input", `{"status":"upcoming"}`)
	if code != 0 {
		t.Fatalf("outcome = %d %v (stderr %q)", code, out, h.lastStderr)
	}
	events := out["result"].(map[string]any)["events"].([]any)
	if len(events) != 1 || events[0].(map[string]any)["title"] != "Conf 2026" {
		t.Fatalf("result = %v", out["result"])
	}
	if rec := h.auditRecord(); rec["credential_subject"] != "connector:"+execConnector || rec["credential_source"] != "opaque_ref" {
		t.Fatalf("audit = %v", rec)
	}
}

func TestConnectorInvokeLinearIssueRead(t *testing.T) {
	h := newExecHarness(t)
	caps := `[{"name":"issue.read","action":"read"}]`
	h.catalogBody = allowJSON(envelopeJSON("issue.read", "read", "linear/issue/ENG-1", execUser),
		descriptorJSON("linear", "oauth", "per_user", "", caps, ""), oauthJSON(h.now.Add(time.Minute)))
	h.transport.routes["api.linear.app"] = func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); !strings.Contains(got, execToken) {
			t.Errorf("linear authorization = %q", got)
		}
		_, _ = io.WriteString(w, `{"data":{"issue":{"id":"i-1","identifier":"ENG-1","title":"Fix it","state":{"name":"Todo"},"team":{"key":"ENG"},"project":null}}}`)
	}
	out, code := h.run("--capability", "issue.read", "--action", "read", "--resource", "linear/issue/ENG-1", "--user", execUser)
	if code != 0 {
		t.Fatalf("outcome = %d %v (stderr %q)", code, out, h.lastStderr)
	}
	if out["result"].(map[string]any)["identifier"] != "ENG-1" {
		t.Fatalf("result = %v", out["result"])
	}
}

func TestConnectorInvokeDriveListFilesUsesReadPolicyAndBoundedProviderQuery(t *testing.T) {
	h := newExecHarness(t)
	caps := `[{"name":"drive.search","action":"read"}]`
	h.catalogBody = allowJSON(envelopeJSON("drive.search", "read", "drive/0AFx", execUser),
		descriptorJSON("google_drive", "oauth", "per_user", "", caps, ""), oauthJSON(h.now.Add(time.Minute)))
	h.transport.routes["www.googleapis.com"] = func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/drive/v3/files" || r.URL.Query().Get("driveId") != "0AFx" || r.URL.Query().Get("pageSize") != "" {
			t.Errorf("provider list request = %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		q := r.URL.Query().Get("q")
		if !strings.Contains(q, "trashed = false") || !strings.Contains(q, "name contains 'plan'") || strings.Contains(q, "mimeType") {
			t.Errorf("provider filter = %q", q)
		}
		_, _ = io.WriteString(w, `{"files":[{"id":"f-1","driveId":"0AFx","name":"Plan","mimeType":"text/plain","modifiedTime":"2026-09-01T00:00:00Z","content":"must not be returned"},{"id":"f-2","driveId":"0AFx","name":"Plan document","mimeType":"application/vnd.google-apps.document"},{"id":"f-3","driveId":"other-drive","name":"Plan other","mimeType":"text/plain"}]}`)
	}
	out, code := h.run("--capability", "drive.search", "--action", "read", "--resource", "drive/0AFx", "--user", execUser, "--input", `{"query":"plan","mime_type":"text/plain","limit":10}`)
	if code != 0 {
		t.Fatalf("outcome = %d %v (stderr %q)", code, out, h.lastStderr)
	}
	result := fmt.Sprint(out["result"])
	if !strings.Contains(result, "f-1") || strings.Contains(result, "f-2") || strings.Contains(result, "f-3") || strings.Contains(result, "must not be returned") {
		t.Fatalf("normalized result = %v", out["result"])
	}
	catalogJSON, _ := json.Marshal(h.catalogReqs)
	for _, privateInput := range []string{"plan", "mime_type", "text/plain", "limit"} {
		if strings.Contains(string(catalogJSON), privateInput) {
			t.Fatalf("provider input %q reached the policy catalog: %s", privateInput, catalogJSON)
		}
	}
}

func TestConnectorInvokeDriveListFilesRejectsBackslashQueryBeforeProvider(t *testing.T) {
	h := newExecHarness(t)
	caps := `[{"name":"drive.search","action":"read"}]`
	h.catalogBody = allowJSON(envelopeJSON("drive.search", "read", "drive/0AFx", execUser),
		descriptorJSON("google_drive", "oauth", "per_user", "", caps, ""), oauthJSON(h.now.Add(time.Minute)))
	out, code := h.run("--capability", "drive.search", "--action", "read", "--resource", "drive/0AFx", "--user", execUser,
		"--input", `{"query":"\\\\' or trashed != true"}`)
	h.assertDeny(out, code, "input_invalid")
	if h.catalogCalled != 1 || h.transport.callCount() != 0 {
		t.Fatalf("invalid query reached catalog %d times or provider %d times", h.catalogCalled, h.transport.callCount())
	}
	catalogJSON, _ := json.Marshal(h.catalogReqs)
	if strings.Contains(string(catalogJSON), "trashed") || strings.Contains(string(catalogJSON), "query") {
		t.Fatalf("raw invalid input reached catalog: %s", catalogJSON)
	}
}

// Every credential and catalog failure denies with a reason code and makes no
// provider call.
const notionCaps = `[{"name":"search","action":"read"},{"name":"page.read","action":"read"},{"name":"database.query","action":"read"}]`

// Notion resolves its integration token from the tenant secret store (path
// 1). The query stays in the input: the catalog sees only its digest.
func TestConnectorInvokeNotionSearchUsesSharedSecret(t *testing.T) {
	h := newExecHarness(t)
	h.store.values[execBackend+"|"+execSecretRef] = execNotionTok
	h.catalogBody = allowJSON(envelopeJSON("search", "read", "search", execUser), descriptorJSON("notion", "opaque_ref", "", "", notionCaps, ""), "")
	h.transport.routes["api.notion.com"] = func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+execNotionTok {
			t.Errorf("notion authorization = %q", got)
		}
		_, _ = io.WriteString(w, `{"results":[{"object":"page","id":"1a2b3c4d5e6f47a8b9c0d1e2f3a4b5c6","url":"https://www.notion.so/p","parent":{"type":"workspace","workspace":true},"properties":{"Name":{"type":"title","title":[{"plain_text":"Roadmap"}]},"Notes":{"type":"rich_text","rich_text":[{"plain_text":"secret notes"}]}}}],"has_more":false}`)
	}
	out, code := h.run("--capability", "search", "--action", "read", "--resource", "search", "--user", execUser, "--input", `{"query":"roadmap"}`)
	if code != 0 {
		t.Fatalf("outcome = %d %v (stderr %q)", code, out, h.lastStderr)
	}
	results := out["result"].(map[string]any)["results"].([]any)
	if len(results) != 1 || results[0].(map[string]any)["title"] != "Roadmap" || strings.Contains(h.lastStdout, "secret notes") {
		t.Fatalf("result = %v", out["result"])
	}
	catalogSent, _ := json.Marshal(h.catalogReqs)
	if strings.Contains(string(catalogSent), "roadmap") || strings.Contains(strings.Join(h.lastAuditLines, "\n"), "roadmap") {
		t.Fatalf("the query left the runtime: catalog %s audit %v", catalogSent, h.lastAuditLines)
	}
	if rec := h.auditRecord(); rec["credential_subject"] != "connector:"+execConnector || rec["credential_source"] != "opaque_ref" {
		t.Fatalf("audit = %v", rec)
	}
}

// pde-harness sends notion_search as --resource notion/workspace. That is not
// a contract resource, so the runtime denies it without calling Notion.
func TestConnectorInvokeNotionRejectsPDEWorkspaceResource(t *testing.T) {
	h := newExecHarness(t)
	h.store.values[execBackend+"|"+execSecretRef] = execNotionTok
	h.catalogBody = allowJSON(envelopeJSON("search", "read", "notion/workspace", execUser), descriptorJSON("notion", "opaque_ref", "", "", notionCaps, ""), "")
	out, code := h.run("--capability", "search", "--action", "read", "--resource", "notion/workspace", "--user", execUser)
	h.assertDeny(out, code, "input_invalid")
	if n := h.transport.callCount(); n != 0 {
		t.Fatalf("provider calls = %d", n)
	}
}

func TestConnectorInvokeFailsClosedWithoutCallingTheProvider(t *testing.T) {
	titoCaps := `[{"name":"event.list","action":"read"}]`
	titoAllow := allowJSON(envelopeJSON("event.list", "read", "tito/acme/events", execUser),
		descriptorJSON("tito", "opaque_ref", "", "", titoCaps, ""), "")
	gmailEnv := envelopeJSON("message.search", "read", "gmail/messages", execUser)
	gmailDesc := descriptorJSON("gmail", "oauth", "per_user", "", gmailCaps, "")
	now := time.Now().UTC()

	cases := []struct {
		name       string
		setup      func(h *execHarness)
		args       []string
		reasonCode string
	}{
		{"missing secret", func(h *execHarness) { h.catalogBody = titoAllow }, nil, "credential_unavailable"},
		{"unregistered backend", func(h *execHarness) {
			h.catalogBody = strings.Replace(titoAllow, execBackend, "gcp-secret-manager", 1)
		}, nil, "credential_backend_unavailable"},
		{"not connected", func(h *execHarness) {
			h.catalogBody = `{"decision":"deny","reason_code":"oauth_not_connected","reason":"no gmail connection","connect":{"provider":"gmail","url":"https://kei.example/connect#x"}}`
		}, nil, "oauth_not_connected"},
		{"revoked binding", func(h *execHarness) {
			h.catalogBody = `{"decision":"deny","reason_code":"oauth_reconnect_required","reason":"refresh failed"}`
		}, nil, "oauth_reconnect_required"},
		{"binding mismatch", func(h *execHarness) {
			h.catalogBody = `{"decision":"deny","reason_code":"oauth_binding_mismatch","reason":"binding"}`
		}, nil, "oauth_binding_mismatch"},
		{"bridge down", func(h *execHarness) {
			h.catalogBody = `{"decision":"deny","reason_code":"oauth_bridge_unavailable","reason":"bridge"}`
		}, nil, "oauth_bridge_unavailable"},
		{"policy deny without code", func(h *execHarness) {
			h.catalogBody = `{"decision":"deny","reason":"no matching policy"}`
		}, nil, "policy_deny"},
		{"enrollment", func(h *execHarness) {
			h.catalogBody = `{"decision":"deny","reason_code":"enrollment_required","reason":"link","enrollment":{"url":"https://kei.example/identity/link#claim=x"}}`
		}, nil, "enrollment_required"},
		{"catalog error", func(h *execHarness) { h.catalogStatus = http.StatusInternalServerError; h.catalogBody = "boom" }, nil, "catalog_unavailable"},
		{"oauth block missing", func(h *execHarness) { h.catalogBody = allowJSON(gmailEnv, gmailDesc, "") }, nil, "descriptor_invalid"},
		{"oauth on opaque_ref", func(h *execHarness) {
			h.catalogBody = allowJSON(envelopeJSON("event.list", "read", "tito/acme/events", execUser), descriptorJSON("tito", "opaque_ref", "", "", titoCaps, ""), oauthJSON(now.Add(time.Minute)))
		}, nil, "descriptor_invalid"},
		{"descriptor missing", func(h *execHarness) { h.catalogBody = `{"decision":"allow","envelope":` + gmailEnv + `}` }, nil, "descriptor_invalid"},
		{"other connector", func(h *execHarness) {
			h.catalogBody = allowJSON(gmailEnv, strings.Replace(gmailDesc, execConnector, "77777777-7777-7777-7777-777777777777", 1), oauthJSON(now.Add(time.Minute)))
		}, nil, "descriptor_invalid"},
		{"expired token", func(h *execHarness) { h.catalogBody = allowJSON(gmailEnv, gmailDesc, oauthJSON(now.Add(-time.Second))) }, nil, "oauth_token_expired"},
		{"plain http control plane", func(h *execHarness) {
			h.catalogBody = allowJSON(gmailEnv, gmailDesc, oauthJSON(now.Add(time.Minute)))
			h.controlPlane = "http://kei.example.com"
		}, nil, "insecure_transport"},
		{"s3 dropped", func(h *execHarness) {
			h.catalogBody = allowJSON(envelopeJSON("object.read", "read", "s3://b/k", execUser), descriptorJSON("s3", "opaque_ref", "", "", `[{"name":"object.read","action":"read"}]`, ""), "")
		}, nil, "provider_not_supported"},
		{"delegation not yet", func(h *execHarness) {
			h.catalogBody = allowJSON(gmailEnv, descriptorJSON("gmail", "opaque_ref", "domain_delegation", "", gmailCaps, `,"config":{"impersonate_email":"events@example.com"}`), "")
		}, nil, "account_model_not_supported"},
		{"write capability not executed", func(h *execHarness) {
			h.catalogBody = allowJSON(envelopeJSON("issue.update", "update", "linear/issue/ENG-1", execUser), descriptorJSON("linear", "oauth", "per_user", "", `[{"name":"issue.update","action":"update"}]`, ""), oauthJSON(now.Add(time.Minute)))
		}, []string{"--capability", "issue.update", "--action", "update", "--resource", "linear/issue/ENG-1"}, "capability_not_supported"},
		{"linear write without idempotency key", func(h *execHarness) {
			h.catalogBody = allowJSON(envelopeJSON("issue.create", "create", "linear/team/ENG", execUser), linearWriteDescriptor(), oauthJSON(now.Add(time.Minute)))
		}, []string{"--capability", "issue.create", "--action", "create", "--resource", "linear/team/ENG", "--input", `{"team_id":"ENG","title":"t"}`}, "input_invalid"},
		{"linear write envelope drops the idempotency key", func(h *execHarness) {
			h.catalogBody = allowJSON(envelopeJSON("issue.create", "create", "linear/team/ENG", execUser), linearWriteDescriptor(), oauthJSON(now.Add(time.Minute)))
		}, []string{"--capability", "issue.create", "--action", "create", "--resource", "linear/team/ENG", "--idempotency-key", "idem-1", "--input", `{"team_id":"ENG","title":"t"}`}, "descriptor_invalid"},
		{"linear issue.create team_id differs from resource", func(h *execHarness) {
			h.catalogBody = allowJSON(linearWriteEnvelope("issue.create", "linear/team/ENG"), linearWriteDescriptor(), oauthJSON(now.Add(time.Minute)))
		}, []string{"--capability", "issue.create", "--action", "create", "--resource", "linear/team/ENG", "--idempotency-key", "idem-1", "--input", `{"team_id":"OPS","title":"t"}`}, "input_invalid"},
		{"linear issue.create unknown field", func(h *execHarness) {
			h.catalogBody = allowJSON(linearWriteEnvelope("issue.create", "linear/team/ENG"), linearWriteDescriptor(), oauthJSON(now.Add(time.Minute)))
		}, []string{"--capability", "issue.create", "--action", "create", "--resource", "linear/team/ENG", "--idempotency-key", "idem-1", "--input", `{"team_id":"ENG","title":"t","labels":"bug"}`}, "input_invalid"},
		{"linear write scope not granted", func(h *execHarness) {
			h.catalogBody = allowJSON(linearWriteEnvelope("issue.create", "linear/team/ENG"), strings.Replace(linearWriteDescriptor(), `"scopes":["read","issues:create","comments:create"]`, `"scopes":["read"]`, 1), oauthJSON(now.Add(time.Minute)))
		}, []string{"--capability", "issue.create", "--action", "create", "--resource", "linear/team/ENG", "--idempotency-key", "idem-1", "--input", `{"team_id":"ENG","title":"t"}`}, "input_invalid"},
		{"unknown input field", func(h *execHarness) { h.catalogBody = allowJSON(gmailEnv, gmailDesc, oauthJSON(now.Add(time.Minute))) },
			[]string{"--capability", "message.search", "--action", "read", "--resource", "gmail/messages", "--input", `{"query":"x","body":true}`}, "input_invalid"},
		{"page size too large", func(h *execHarness) { h.catalogBody = allowJSON(gmailEnv, gmailDesc, oauthJSON(now.Add(time.Minute))) },
			[]string{"--capability", "message.search", "--action", "read", "--resource", "gmail/messages", "--input", `{"page_size":500}`}, "input_invalid"},
		// Notion runs on a shared integration token only; there is no Notion
		// OAuth in the bridge, so an oauth descriptor is refused.
		{"notion oauth", func(h *execHarness) {
			h.catalogBody = allowJSON(envelopeJSON("search", "read", "search", execUser), descriptorJSON("notion", "oauth", "", execUser, notionCaps, ""), oauthJSON(now.Add(time.Minute)))
		}, []string{"--capability", "search", "--action", "read", "--resource", "search"}, "descriptor_invalid"},
		{"notion query in resource", func(h *execHarness) {
			h.store.values[execBackend+"|"+execSecretRef] = execNotionTok
			h.catalogBody = allowJSON(envelopeJSON("search", "read", "search/roadmap", execUser), descriptorJSON("notion", "opaque_ref", "", "", notionCaps, ""), "")
		}, []string{"--capability", "search", "--action", "read", "--resource", "search/roadmap"}, "input_invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newExecHarness(t)
			h.now = now
			tc.setup(h)
			h.routeGmail()
			args := tc.args
			if args == nil {
				args = []string{"--capability", "event.list", "--action", "read", "--resource", "tito/acme/events"}
				if strings.Contains(h.catalogBody, "gmail") {
					args = []string{"--capability", "message.search", "--action", "read", "--resource", "gmail/messages"}
				}
				if strings.Contains(h.catalogBody, "object.read") {
					args = []string{"--capability", "object.read", "--action", "read", "--resource", "s3://b/k"}
				}
			}
			out, code := h.run(append(args, "--user", execUser)...)
			h.assertDeny(out, code, tc.reasonCode)
			if n := h.transport.callCount(); n != 0 {
				t.Fatalf("provider called %d times on a deny", n)
			}
			if rec := h.auditRecord(); rec["decision"] != "deny" || rec["policy_reason"] != tc.reasonCode {
				t.Fatalf("audit = %v", rec)
			}
			if tc.reasonCode == "oauth_not_connected" && out["connect"] == nil {
				t.Fatal("connect link was not passed through")
			}
			if tc.reasonCode == "enrollment_required" && out["enrollment"] == nil {
				t.Fatal("enrollment was not passed through")
			}
		})
	}
}

// Input that is not a JSON object, or is too large, is rejected before the
// catalog is asked anything.
func TestConnectorInvokeRejectsMalformedInputBeforeTheCatalog(t *testing.T) {
	for name, input := range map[string]string{
		"not json":   `{"query":`,
		"not object": `["a"]`,
		"too large":  `{"query":"` + strings.Repeat("a", 17<<10) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			h := newExecHarness(t)
			out, code := h.run("--capability", "message.search", "--action", "read", "--resource", "gmail/messages", "--user", execUser, "--input", input)
			h.assertDeny(out, code, "input_invalid")
			if h.catalogCalled != 0 {
				t.Fatal("catalog was called with invalid input")
			}
		})
	}
}

// Provider failures map to reason codes by HTTP status and never return data.
func TestConnectorInvokeMapsProviderFailures(t *testing.T) {
	for status, reason := range map[int]string{
		http.StatusUnauthorized:        "provider_denied",
		http.StatusForbidden:           "provider_denied",
		http.StatusNotFound:            "provider_not_found",
		http.StatusTooManyRequests:     "provider_rate_limited",
		http.StatusInternalServerError: "provider_error",
	} {
		t.Run(reason+fmt.Sprint(status), func(t *testing.T) {
			h := newExecHarness(t)
			h.gmailPerUserAllow()
			h.transport.routes["gmail.googleapis.com"] = func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				_, _ = io.WriteString(w, `{"error":"provider said no with detail"}`)
			}
			out, code := h.run("--capability", "message.search", "--action", "read", "--resource", "gmail/messages", "--user", execUser)
			h.assertDeny(out, code, reason)
			if strings.Contains(h.lastStdout+h.lastStderr, "provider said no") {
				t.Fatal("provider error body leaked")
			}
		})
	}
}

func TestConnectorInvokeRejectsOversizedProviderResponse(t *testing.T) {
	h := newExecHarness(t)
	h.gmailPerUserAllow()
	h.transport.routes["gmail.googleapis.com"] = func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"messages":[],"padding":"`+strings.Repeat("x", 5<<20)+`"}`)
	}
	out, code := h.run("--capability", "message.search", "--action", "read", "--resource", "gmail/messages", "--user", execUser)
	h.assertDeny(out, code, "result_too_large")
}

const crmCaps = `[{"name":"lead.read","action":"read"},{"name":"lead.create","action":"create"},{"name":"lead.update","action":"update"}]`

func (h *execHarness) crmAllow() {
	h.store.values[execBackend+"|"+execSecretRef] = execCRMKey
	h.catalogBody = allowJSON(envelopeJSON("lead.read", "read", "leads", execUser),
		descriptorJSON("crm", "opaque_ref", "", "", crmCaps, `,"config":{"base_url":"`+execCRMBaseURL+`","assertion_audience":"kei-crm","allowed_resources":["leads"]}`), "")
}

// CRM reads go to the MarketingSite Worker with the connector API key and a
// service assertion the runtime signs with its installation key (D3). Free
// text the Worker returns is dropped.
func TestConnectorInvokeCRMLeadReadSignsAssertion(t *testing.T) {
	h := newExecHarness(t)
	h.enableAssertionKey()
	h.crmAllow()
	h.transport.routes["crm.example.com"] = func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/crm/v1/invoke" {
			t.Errorf("crm request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-KEI-API-Key") != execCRMKey {
			t.Errorf("crm api key header missing")
		}
		header, claims := verifyES256(t, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), &h.assertionKey.PublicKey)
		if header["kid"] != execAssertKID || header["alg"] != "ES256" {
			t.Errorf("assertion header = %v", header)
		}
		exp, iat := claims["exp"].(float64), claims["iat"].(float64)
		if claims["iss"] != "kei-runtime:"+execInstall || claims["aud"] != "kei-crm" || exp-iat != 60 || claims["jti"] == "" ||
			claims["tenant_id"] != execTenant || claims["workspace_id"] != execWorkspace || claims["subject"] != execUser ||
			claims["agent_id"] != execAgent || claims["connector_id"] != execConnector || claims["provider"] != "crm" ||
			claims["connector_status"] != "active" || claims["capability"] != "lead.read" || claims["action"] != "read" ||
			claims["resource"] != "leads" || claims["trace_id"] != execTrace {
			t.Errorf("assertion claims = %v", claims)
		}
		caps := fmt.Sprint(claims["capabilities"])
		if !strings.Contains(caps, "map[action:read name:lead.read]") || !strings.Contains(caps, "map[action:create name:lead.create]") {
			t.Errorf("assertion capabilities = %v", caps)
		}
		if fmt.Sprint(claims["policy"]) != "map[allowed_actions:[read] allowed_resources:[leads]]" {
			t.Errorf("assertion policy = %v", claims["policy"])
		}
		_, _ = io.WriteString(w, `{"success":true,"data":{"records":[{"id":7,"company_name":"Acme","contact_name":"Ann","email":"ann@acme.test","role":"cto","status":"new","priority":"high","source":"audit","tier":null,"created_at":"2026-09-01","updated_at":"2026-09-02","message":"PRIVATE FREE TEXT","early_access_notes":"PRIVATE NOTES"}]}}`)
	}
	out, code := h.run("--capability", "lead.read", "--action", "read", "--resource", "leads", "--user", execUser)
	if code != 0 {
		t.Fatalf("outcome = %d %v (stderr %q)", code, out, h.lastStderr)
	}
	records := out["result"].(map[string]any)["records"].([]any)
	lead := records[0].(map[string]any)
	if lead["company_name"] != "Acme" || lead["email"] != "ann@acme.test" {
		t.Fatalf("lead = %v", lead)
	}
	if strings.Contains(h.lastStdout, "PRIVATE") {
		t.Fatal("CRM free text was returned")
	}
	if rec := h.auditRecord(); rec["assertion_kid"] != execAssertKID {
		t.Fatalf("audit = %v", rec)
	}
}

func TestConnectorInvokeCRMWithoutAssertionKeyDenies(t *testing.T) {
	h := newExecHarness(t)
	h.crmAllow()
	out, code := h.run("--capability", "lead.read", "--action", "read", "--resource", "leads", "--user", execUser)
	h.assertDeny(out, code, "assertion_key_unavailable")
	if h.transport.callCount() != 0 {
		t.Fatal("CRM was called without an assertion")
	}
}

// http_api keeps the existing governed HTTP path: one registered base URL and
// the injected shared-secret key.
const httpAPIBlock = `,"http_api":{"registered_base_url":"https://api.example.com/v1","registered_hostname":"api.example.com","allowed_methods":["GET"],"allowed_path_patterns":["/contacts/*","/leads"],"query_allowlist":["limit"],"request_max_bytes":1024,"response_max_bytes":65536,"timeout_ms":5000,"credential_injection":{"location":"header","name":"X-API-Key"},"redaction":{"headers":["X-API-Key"],"query_parameters":[],"response_fields":["email"]}}`

// TestHTTPAPIRebindingIsBlockedAtDial checks that the dial-level SSRF guard
// catches a DNS-rebinding attack. The contract rejects loopback hostnames, so
// this test verifies the guarded transport directly: a TLS server on loopback
// receives zero connections when dialed through GuardedHTTPTransport.
func TestHTTPAPIRebindingIsBlockedAtDial(t *testing.T) {
	var mu sync.Mutex
	connState := map[http.ConnState]int{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If we get here the guard failed.
	}))
	srv.Config.ConnState = func(c net.Conn, s http.ConnState) {
		mu.Lock()
		connState[s]++
		mu.Unlock()
	}
	srv.Start()
	defer srv.Close()

	transport := httpapi.GuardedHTTPTransport()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	_, err := client.Get(srv.URL)

	mu.Lock()
	newConns := connState[http.StateNew]
	mu.Unlock()

	if err == nil {
		t.Fatalf("expected dial error for loopback address, got nil (server received %d connections)", newConns)
	}
	if newConns > 0 {
		t.Fatalf("loopback server received %d connections (expected 0) — the guard did not block the dial", newConns)
	}
	t.Logf("guarded transport correctly blocked loopback dial: %v", err)
}

// httpAPIAllow is a catalog allow for http.get on resource, the exact request
// path the catalog authorized.
func (h *execHarness) httpAPIAllow(resource string) {
	h.store.values[execBackend+"|"+execSecretRef] = execCRMKey
	h.catalogBody = allowJSON(envelopeJSON("http.get", "read", resource, execUser),
		descriptorJSON("http_api", "opaque_ref", "", "", `[{"name":"http.get","action":"read"}]`, httpAPIBlock), "")
}

// http_api keeps the existing governed HTTP path: one registered base URL and
// the injected shared-secret key.
func TestConnectorInvokeHTTPAPIGet(t *testing.T) {
	h := newExecHarness(t)
	h.httpAPIAllow("/leads")
	h.transport.routes["api.example.com"] = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/leads" || r.URL.Query().Get("limit") != "5" || r.Header.Get("X-API-Key") != execCRMKey {
			t.Errorf("http_api request = %s %v", r.URL, r.Header)
		}
		_, _ = io.WriteString(w, `{"records":[{"id":1,"email":"x@example.test"}]}`)
	}
	out, code := h.run("--capability", "http.get", "--action", "read", "--resource", "/leads", "--user", execUser, "--input", `{"path":"/leads","query":{"limit":["5"]}}`)
	if code != 0 {
		t.Fatalf("outcome = %d %v (stderr %q)", code, out, h.lastStderr)
	}
	result := out["result"].(map[string]any)
	if result["status_code"].(float64) != 200 || strings.Contains(fmt.Sprint(result["body"]), "x@example.test") {
		t.Fatalf("result = %v", result)
	}
}

// http_api writes run through the same governed path: the declared JSON
// body reaches the provider intact beside the shared-secret header, and
// neither the body nor the secret lands in stdout, stderr, or audit. The
// runtime sends the canonical input the catalog authorized by digest (sorted
// keys, numbers as written), so body is already canonical here.
func TestConnectorInvokeHTTPAPIPostAndPatchSendTheBody(t *testing.T) {
	const body = `{"amount":1.50,"name":"Ada","note":"private-body-marker","stage":"seed"}`
	for capability, action := range map[string]string{"http.post": "create", "http.patch": "update"} {
		t.Run(capability, func(t *testing.T) {
			h := newExecHarness(t)
			h.store.values[execBackend+"|"+execSecretRef] = execCRMKey
			block := strings.Replace(httpAPIBlock, `"allowed_methods":["GET"]`, `"allowed_methods":["GET","POST","PATCH"]`, 1)
			descriptor := strings.Replace(descriptorJSON("http_api", "opaque_ref", "", "", `[{"name":"http.get","action":"read"},{"name":"http.post","action":"create"},{"name":"http.patch","action":"update"}]`, block),
				`"allowed_actions":["read"]`, `"allowed_actions":["read","create","update"]`, 1)
			envelope := strings.Replace(envelopeJSON(capability, action, "/leads", execUser), `"trace_id":`, `"idempotency_key":"idem-1","trace_id":`, 1)
			h.catalogBody = allowJSON(envelope, descriptor, "")
			method := strings.ToUpper(strings.TrimPrefix(capability, "http."))
			h.transport.routes["api.example.com"] = func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				if r.Method != method || r.URL.Path != "/v1/leads" || string(raw) != body || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("X-API-Key") != execCRMKey {
					t.Errorf("http_api request = %s %s %q %v", r.Method, r.URL, raw, r.Header)
				}
				_, _ = io.WriteString(w, `{"id":7}`)
			}
			out, code := h.run("--capability", capability, "--action", action, "--resource", "/leads", "--user", execUser, "--idempotency-key", "idem-1", "--input", `{"path":"/leads","body":`+body+`}`)
			if code != 0 || out["decision"] != "allow" || h.transport.callCount() != 1 {
				t.Fatalf("outcome = %d %v (stderr %q)", code, out, h.lastStderr)
			}
			for name, text := range map[string]string{"stdout": h.lastStdout, "stderr": h.lastStderr, "audit": strings.Join(h.lastAuditLines, "\n")} {
				if strings.Contains(text, "private-body-marker") {
					t.Fatalf("%s carried the request body: %s", name, text)
				}
			}
		})
	}
}

// The catalog authorizes one resource: the exact request path. The runtime
// must call that path and no other, or a harness could get an allow for
// /contacts/1 and read /contacts/999 (HAI-256). A mismatch denies before any
// secret is fetched.
func TestConnectorInvokeHTTPAPIPathMustEqualTheAuthorizedResource(t *testing.T) {
	h := newExecHarness(t)
	h.httpAPIAllow("/contacts/1")
	h.transport.routes["api.example.com"] = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/contacts/1" {
			t.Errorf("http_api called %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"id":1}`)
	}
	out, code := h.run("--capability", "http.get", "--action", "read", "--resource", "/contacts/1", "--user", execUser, "--input", `{"path":"/contacts/1"}`)
	if code != 0 || out["decision"] != "allow" {
		t.Fatalf("equal path: outcome = %d %v (stderr %q)", code, out, h.lastStderr)
	}

	for name, tc := range map[string]struct{ resource, path string }{
		"different path":          {"/contacts/1", "/contacts/999"},
		"prefix of the resource":  {"/contacts/1", "/contacts"},
		"trailing slash":          {"/contacts/1", "/contacts/1/"},
		"traversal":               {"/contacts/1", "/contacts/1/../999"},
		"encoded traversal":       {"/contacts/1", "/contacts/1/%2e%2e/999"},
		"encoded slash":           {"/contacts/1", "/contacts%2f999"},
		"added query":             {"/contacts/1", "/contacts/1?id=999"},
		"query on both":           {"/contacts/1?id=1", "/contacts/1?id=1"},
		"traversal on both":       {"/contacts/../admin", "/contacts/../admin"},
		"encoded traversal both":  {"/contacts/%2E%2E/admin", "/contacts/%2E%2E/admin"},
		"absolute url":            {"/contacts/1", "https://evil.example/contacts/1"},
		"absolute on both":        {"https://evil.example/x", "https://evil.example/x"},
		"scheme-relative on both": {"//evil.example/x", "//evil.example/x"},
		"relative on both":        {"contacts/1", "contacts/1"},
		"fragment":                {"/contacts/1", "/contacts/1#999"},
		"backslash on both":       {"/contacts\\1", "/contacts\\1"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newExecHarness(t)
			h.httpAPIAllow(tc.resource)
			in, _ := json.Marshal(map[string]string{"path": tc.path})
			out, code := h.run("--capability", "http.get", "--action", "read", "--resource", tc.resource, "--user", execUser, "--input", string(in))
			h.assertDeny(out, code, "input_invalid")
			if h.store.gets != 0 {
				t.Fatalf("secret store consulted %d times for a mismatched path", h.store.gets)
			}
			if h.transport.callCount() != 0 {
				t.Fatal("the HTTP API was called")
			}
		})
	}
}

func verifyES256(t *testing.T, token string, pub *ecdsa.PublicKey) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("assertion is not a JWS: %q", token)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		t.Fatalf("assertion signature malformed")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("assertion signature does not verify")
	}
	decode := func(s string) map[string]any {
		raw, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	return decode(parts[0]), decode(parts[1])
}

// A crm connector without its Worker origin is a catalog/descriptor problem,
// not bad input.
func TestConnectorInvokeCRMWithoutBaseURLIsDescriptorInvalid(t *testing.T) {
	h := newExecHarness(t)
	h.enableAssertionKey()
	h.store.values[execBackend+"|"+execSecretRef] = execCRMKey
	h.catalogBody = allowJSON(envelopeJSON("lead.read", "read", "leads", execUser),
		descriptorJSON("crm", "opaque_ref", "", "", crmCaps, ""), "")
	out, code := h.run("--capability", "lead.read", "--action", "read", "--resource", "leads", "--user", execUser)
	h.assertDeny(out, code, "descriptor_invalid")
	if h.transport.callCount() != 0 {
		t.Fatal("CRM was called without a configured origin")
	}
}

// A connector secret delivered by the control plane (HAI-262) lives at a
// backend-qualified location the opaque credential_ref cannot spell; the
// descriptor carries it as credential_secret_ref and the runtime reads it.
func TestConnectorInvokeReadsTheDeliveredSecretRef(t *testing.T) {
	h := newExecHarness(t)
	delivered := "aws-secrets-manager://us-west-2/" + execSecretRef
	h.store.values[execBackend+"|"+delivered] = execTitoToken
	caps := `[{"name":"event.list","action":"read"}]`
	h.catalogBody = allowJSON(envelopeJSON("event.list", "read", "tito/acme/events", execUser),
		descriptorJSON("tito", "opaque_ref", "", "", caps, fmt.Sprintf(`,"config":{"account_slug":"acme"},"credential_secret_ref":%q`, delivered)), "")
	h.transport.routes["api.tito.io"] = func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Token token="+execTitoToken {
			t.Errorf("tito authorization = %q", got)
		}
		_, _ = io.WriteString(w, `{"events":[],"meta":{"next_page":null}}`)
	}
	out, code := h.run("--capability", "event.list", "--action", "read", "--resource", "tito/acme/events", "--user", execUser, "--input", `{"status":"upcoming"}`)
	if code != 0 {
		t.Fatalf("outcome = %d %v (stderr %q)", code, out, h.lastStderr)
	}
}

// A credential_secret_ref that does not name the connector's credential_ref
// is a descriptor the runtime refuses before reading any secret.
func TestConnectorInvokeRejectsASecretRefForAnotherName(t *testing.T) {
	h := newExecHarness(t)
	other := "aws-secrets-manager://us-west-2/kei/other/connectors/x/api_token"
	h.store.values[execBackend+"|"+other] = execTitoToken
	caps := `[{"name":"event.list","action":"read"}]`
	h.catalogBody = allowJSON(envelopeJSON("event.list", "read", "tito/acme/events", execUser),
		descriptorJSON("tito", "opaque_ref", "", "", caps, fmt.Sprintf(`,"config":{"account_slug":"acme"},"credential_secret_ref":%q`, other)), "")
	h.transport.routes["api.tito.io"] = func(w http.ResponseWriter, r *http.Request) {
		t.Error("provider called with a mismatched secret reference")
	}
	out, code := h.run("--capability", "event.list", "--action", "read", "--resource", "tito/acme/events", "--user", execUser, "--input", `{"status":"upcoming"}`)
	h.assertDeny(out, code, "descriptor_invalid")
}

// linearWriteDescriptor is a per_user Linear connector that declares the
// executed writes and whose scopes are the Linear OAuth scopes they need.
func linearWriteDescriptor() string {
	caps := `[{"name":"team.read","action":"read"},{"name":"issue.create","action":"create"},{"name":"comment.create","action":"create"}]`
	return strings.Replace(descriptorJSON("linear", "oauth", "per_user", "", caps, ""), `"scopes":["read"]`, `"scopes":["read","issues:create","comments:create"]`, 1)
}

// linearWriteEnvelope is the catalog envelope for a write, carrying the
// request's idempotency key.
func linearWriteEnvelope(capability, resource string) string {
	return strings.Replace(envelopeJSON(capability, "create", resource, execUser), `"trace_id":`, `"idempotency_key":"idem-1","trace_id":`, 1)
}

// fakeLinearGraphQL serves the Linear GraphQL operations the writes use and
// records each operation name and its variables.
type fakeLinearGraphQL struct {
	t          *testing.T
	operations []string
	inputs     []map[string]any
	answers    map[string]string
}

func (f *fakeLinearGraphQL) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/graphql" || r.Header.Get("Authorization") != "Bearer "+execToken {
		f.t.Errorf("linear request = %s %s auth %q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
	}
	var body struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		f.t.Errorf("decode linear request: %v", err)
	}
	fields := strings.Fields(body.Query)
	op := strings.SplitN(fields[1], "(", 2)[0]
	f.operations = append(f.operations, op)
	input, _ := body.Variables["input"].(map[string]any)
	f.inputs = append(f.inputs, input)
	answer, ok := f.answers[op]
	if !ok {
		_, _ = io.WriteString(w, `{"data":null,"errors":[{"message":"not found"}]}`)
		return
	}
	_, _ = io.WriteString(w, answer)
}

const linearTeamUUID = "7586c601-2c9f-4764-bbc5-6132791c68c9"

func TestConnectorInvokeLinearIssueCreate(t *testing.T) {
	h := newExecHarness(t)
	h.catalogBody = allowJSON(linearWriteEnvelope("issue.create", "linear/team/ENG"), linearWriteDescriptor(), oauthJSON(h.now.Add(time.Minute)))
	fake := &fakeLinearGraphQL{t: t, answers: map[string]string{
		"TeamID": `{"data":{"teams":{"nodes":[{"id":"` + linearTeamUUID + `","key":"ENG"}]}}}`,
	}}
	h.transport.routes["api.linear.app"] = func(w http.ResponseWriter, r *http.Request) {
		if len(fake.operations) == 1 {
			// The issue id is the write id derived from the idempotency key.
			id := fake.inputsAfter(r)
			fake.answers["IssueCreate"] = `{"data":{"issueCreate":{"success":true,"issue":{"id":"` + id + `","identifier":"ENG-42","url":"https://linear.app/acme/issue/ENG-42","team":{"key":"ENG"}}}}}`
		}
		fake.serve(w, r)
	}
	input := `{"team_id":"ENG","title":"Login crashes","description":"private-bug-body","priority":2}`
	out, code := h.run("--capability", "issue.create", "--action", "create", "--resource", "linear/team/ENG", "--user", execUser, "--idempotency-key", "idem-1", "--input", input)
	if code != 0 {
		t.Fatalf("outcome = %d %v (stderr %q)", code, out, h.lastStderr)
	}
	result := out["result"].(map[string]any)
	if result["identifier"] != "ENG-42" || result["team_key"] != "ENG" || result["url"] != "https://linear.app/acme/issue/ENG-42" {
		t.Fatalf("result = %v", result)
	}
	if got := strings.Join(fake.operations, ","); got != "TeamID,IssueCreate" {
		t.Fatalf("linear operations = %s (the mutation must run exactly once)", got)
	}
	sent := fake.inputs[1]
	if sent["teamId"] != linearTeamUUID || sent["title"] != "Login crashes" || sent["description"] != "private-bug-body" || sent["priority"] != float64(2) || sent["id"] != result["id"] {
		t.Fatalf("issueCreate input = %v", sent)
	}
	rec := h.auditRecord()
	if rec["decision"] != "allow" || rec["tool_name"] != "connector:linear:issue.create" || rec["idempotency_key"] != "idem-1" || rec["input_digest"] == nil || rec["result_digest"] == nil {
		t.Fatalf("audit = %v", rec)
	}
	for _, line := range append(h.lastAuditLines, h.lastStdout) {
		for _, private := range []string{"private-bug-body", "Login crashes", execToken} {
			if strings.Contains(line, private) {
				t.Fatalf("output or audit carries %q: %s", private, line)
			}
		}
	}
}

func TestConnectorInvokeLinearCommentCreate(t *testing.T) {
	h := newExecHarness(t)
	h.catalogBody = allowJSON(linearWriteEnvelope("comment.create", "linear/issue/ENG-42"), linearWriteDescriptor(), oauthJSON(h.now.Add(time.Minute)))
	fake := &fakeLinearGraphQL{t: t, answers: map[string]string{}}
	h.transport.routes["api.linear.app"] = func(w http.ResponseWriter, r *http.Request) {
		id := fake.inputsAfter(r)
		fake.answers["CommentCreate"] = `{"data":{"commentCreate":{"success":true,"comment":{"id":"` + id + `","url":"https://linear.app/acme/issue/ENG-42#comment-1","issue":{"id":"issue-uuid"}}}}}`
		fake.serve(w, r)
	}
	out, code := h.run("--capability", "comment.create", "--action", "create", "--resource", "linear/issue/ENG-42", "--user", execUser, "--idempotency-key", "idem-1", "--input", `{"issue_id":"ENG-42","body":"private-comment-body"}`)
	if code != 0 {
		t.Fatalf("outcome = %d %v (stderr %q)", code, out, h.lastStderr)
	}
	if result := out["result"].(map[string]any); result["issue_id"] != "issue-uuid" {
		t.Fatalf("result = %v", result)
	}
	if got := strings.Join(fake.operations, ","); got != "CommentCreate" {
		t.Fatalf("linear operations = %s", got)
	}
	for _, line := range append(h.lastAuditLines, h.lastStdout) {
		if strings.Contains(line, "private-comment-body") {
			t.Fatalf("output or audit carries the comment body: %s", line)
		}
	}
}

func TestConnectorInvokeLinearIssueCreateFailureDoesNotRetry(t *testing.T) {
	h := newExecHarness(t)
	h.catalogBody = allowJSON(linearWriteEnvelope("issue.create", "linear/team/ENG"), linearWriteDescriptor(), oauthJSON(h.now.Add(time.Minute)))
	fake := &fakeLinearGraphQL{t: t, answers: map[string]string{
		"TeamID": `{"data":{"teams":{"nodes":[{"id":"` + linearTeamUUID + `","key":"ENG"}]}}}`,
	}}
	h.transport.routes["api.linear.app"] = fake.serve
	out, code := h.run("--capability", "issue.create", "--action", "create", "--resource", "linear/team/ENG", "--user", execUser, "--idempotency-key", "idem-1", "--input", `{"team_id":"ENG","title":"t","description":"private-bug-body"}`)
	h.assertDeny(out, code, "provider_error")
	if got := strings.Join(fake.operations, ","); got != "TeamID,IssueCreate,IssueRef" {
		t.Fatalf("linear operations = %s (one mutation, then one replay read)", got)
	}
	if strings.Contains(h.lastStdout, "private-bug-body") {
		t.Fatalf("deny carries the description: %s", h.lastStdout)
	}
}

// TestHTTPAPIDefaultTransportIsGuarded proves the SSRF guard is wired into
// the invoke path. It calls the same selectProviderTransport that run() uses
// and verifies the chosen transport rejects a loopback dial.
func TestHTTPAPIDefaultTransportIsGuarded(t *testing.T) {
	t.Run("http_api uses guarded transport", func(t *testing.T) {
		env := Env{}
		meta := contract.Metadata{Provider: contract.ProviderHTTPAPI}
		rt := env.selectProviderTransport(meta)
		tr, ok := rt.base.(*http.Transport)
		if !ok {
			t.Fatalf("expected *http.Transport, got %T", rt.base)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := tr.DialContext(ctx, "tcp", "127.0.0.1:1")
		if err == nil {
			t.Fatal("guarded transport must deny a loopback dial")
		}
		if !strings.Contains(err.Error(), "blocked") {
			t.Fatalf("guard should fail with 'blocked', got: %v", err)
		}
	})

	t.Run("non-http_api uses default transport", func(t *testing.T) {
		env := Env{}
		meta := contract.Metadata{Provider: contract.ProviderCRM}
		rt := env.selectProviderTransport(meta)
		tr, ok := rt.base.(*http.Transport)
		if !ok {
			t.Fatalf("expected *http.Transport, got %T", rt.base)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := tr.DialContext(ctx, "tcp", "127.0.0.1:1")
		// Default transport does NOT block loopback — it attempts the dial
		// and gets connection refused (or succeeds if something is listening).
		if err == nil {
			return // connected successfully; not a failure
		}
		if strings.Contains(err.Error(), "blocked") {
			t.Fatalf("default transport must not block, got: %v", err)
		}
	})
}

// inputsAfter peeks at the request's input id without consuming the body.
func (f *fakeLinearGraphQL) inputsAfter(r *http.Request) string {
	raw, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(raw))
	var body struct {
		Variables struct {
			Input struct {
				ID string `json:"id"`
			} `json:"input"`
		} `json:"variables"`
	}
	_ = json.Unmarshal(raw, &body)
	return body.Variables.Input.ID
}
