package connectorruntime

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
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// These tests drive `kei-proxy connector invoke` end to end against fakes: a
// fake catalog (real wire client), a fake secret store, and provider fixtures
// routed by host. Nothing touches the network or a real credential.

const (
	execToken      = "fake-oauth-access-token-0001"
	execTitoToken  = "fake-tito-api-token-000000001"
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
		return nil, fmt.Errorf("%w: unknown backend %q", errSecretStore, backend)
	}
	v, ok := s.values[backend+"|"+ref]
	if !ok {
		return nil, errSecretNotFound
	}
	return &v, nil
}
func (s *execSecretStore) Put(context.Context, string, string, string) error { return nil }
func (s *execSecretStore) Delete(context.Context, string, string) error      { return nil }
func (s *execSecretStore) Validate(context.Context, string, string) error    { return nil }

// routeTransport serves provider requests from in-process handlers keyed by
// host, so the real provider clients run unchanged against fixtures.
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
	controlPlane   string // overrides the TLS check target when set
	store          *execSecretStore
	transport      *routeTransport
	auditPath      string
	assertionKey   *ecdsa.PrivateKey
	withAssertion  bool
	stdin          string
	now            time.Time
	catalogCalled  int
	catalogServer  *httptest.Server
	lastStdout     string
	lastStderr     string
	lastAuditLines []string
}

func newExecHarness(t *testing.T) *execHarness {
	t.Helper()
	h := &execHarness{
		t:             t,
		catalogStatus: http.StatusOK,
		store:         &execSecretStore{values: map[string]string{}},
		transport:     &routeTransport{routes: map[string]http.HandlerFunc{}},
		auditPath:     filepath.Join(t.TempDir(), "audit.jsonl"),
		now:           time.Now().UTC(),
	}
	h.catalogServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.catalogCalled++
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		h.catalogReqs = append(h.catalogReqs, body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(h.catalogStatus)
		_, _ = io.WriteString(w, h.catalogBody)
	}))
	t.Cleanup(h.catalogServer.Close)
	t.Setenv("KEI_RUNTIME_TOKEN", "kh_live_exec_runtime_token_0001")
	return h
}

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
	controlPlane := h.catalogServer.URL
	if h.controlPlane != "" {
		controlPlane = h.controlPlane
	}
	rt := connectorRuntime{
		secrets:    h.store,
		httpClient: &http.Client{Transport: h.transport},
		lookupIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		},
		now: func() time.Time { return h.now },
	}
	if h.withAssertion {
		rt.assertion = assertionKeyConfig{backend: execBackend, ref: execAssertRef, kid: execAssertKID}
	}
	deps := connectorInvokeDeps{
		catalog:         NewABACClient(h.catalogServer.URL, "", 5*time.Second),
		controlPlaneURL: controlPlane,
		runtime:         rt,
		stdin:           strings.NewReader(h.stdin),
		auditPath:       h.auditPath,
		auditMaxBytes:   1 << 20,
	}
	base := []string{"--connector", execConnector, "--trace-id", execTrace, "--framework", "pde"}
	code := runConnectorInvokeWith(append(base, args...), deps, &stdout, &stderr)
	h.lastStdout, h.lastStderr = stdout.String(), stderr.String()
	h.lastAuditLines = nil
	if data, err := os.ReadFile(h.auditPath); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line != "" {
				h.lastAuditLines = append(h.lastAuditLines, line)
			}
		}
	}
	var out map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		h.t.Fatalf("stdout is not one JSON object: %q (stderr %q)", stdout.String(), stderr.String())
	}
	// Invariants for every outcome: no credential or sensitive input leaks
	// into stdout, stderr, or the audit spool.
	for _, secret := range []string{execToken, execTitoToken, execCRMKey, "BEGIN PRIVATE KEY", execSecretRef} {
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
	d := fmt.Sprintf(`{"id":%q,"tenant_id":%q,"workspace_id":%q,"name":"conn","provider":%q,"status":"active","credential_source":%q,"credential_ref":%q,"scopes":["read"],"resources":["*"],"policy":{"allowed_actions":["read"],"allowed_resources":["*"]},"capabilities":%s,"created_by":%q`,
		execConnector, execTenant, execWorkspace, provider, source, execSecretRef, capabilities, execUser)
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

func TestConnectorInvokeDriveSearch(t *testing.T) {
	h := newExecHarness(t)
	caps := `[{"name":"drive.search","action":"read"}]`
	h.catalogBody = allowJSON(envelopeJSON("drive.search", "read", "drive/0AFx", execUser),
		descriptorJSON("google_drive", "oauth", "per_user", "", caps, ""), oauthJSON(h.now.Add(time.Minute)))
	h.transport.routes["www.googleapis.com"] = func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"files":[{"id":"f-1","driveId":"0AFx","name":"Plan","mimeType":"application/vnd.google-apps.document","modifiedTime":"2026-09-01T00:00:00Z"}]}`)
	}
	out, code := h.run("--capability", "drive.search", "--action", "read", "--resource", "drive/0AFx", "--user", execUser, "--input", `{"query":"plan"}`)
	if code != 0 {
		t.Fatalf("outcome = %d %v (stderr %q)", code, out, h.lastStderr)
	}
	if !strings.Contains(fmt.Sprint(out["result"]), "Plan") {
		t.Fatalf("result = %v", out["result"])
	}
}

// Every credential and catalog failure denies with a reason code and makes no
// provider call.
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
		{"approval deny without code", func(h *execHarness) {
			h.catalogBody = `{"decision":"deny","reason":"approval required"}`
		}, nil, "approval_required"},
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
		{"write capability", func(h *execHarness) {
			h.catalogBody = allowJSON(envelopeJSON("issue.create", "create", "linear/team/ENG", execUser), descriptorJSON("linear", "oauth", "per_user", "", `[{"name":"issue.create","action":"create"}]`, ""), oauthJSON(now.Add(time.Minute)))
		}, []string{"--capability", "issue.create", "--action", "create", "--resource", "linear/team/ENG"}, "capability_not_supported"},
		{"unknown input field", func(h *execHarness) { h.catalogBody = allowJSON(gmailEnv, gmailDesc, oauthJSON(now.Add(time.Minute))) },
			[]string{"--capability", "message.search", "--action", "read", "--resource", "gmail/messages", "--input", `{"query":"x","body":true}`}, "input_invalid"},
		{"page size too large", func(h *execHarness) { h.catalogBody = allowJSON(gmailEnv, gmailDesc, oauthJSON(now.Add(time.Minute))) },
			[]string{"--capability", "message.search", "--action", "read", "--resource", "gmail/messages", "--input", `{"page_size":500}`}, "input_invalid"},
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
		if !strings.Contains(caps, "map[action:read name:lead.read requires_approval:false]") || !strings.Contains(caps, "map[action:create name:lead.create requires_approval:true]") {
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
func TestConnectorInvokeHTTPAPIGet(t *testing.T) {
	h := newExecHarness(t)
	h.store.values[execBackend+"|"+execSecretRef] = execCRMKey
	httpBlock := `,"http_api":{"registered_base_url":"https://api.example.com/v1","registered_hostname":"api.example.com","allowed_methods":["GET"],"allowed_path_patterns":["/leads"],"query_allowlist":["limit"],"request_max_bytes":1024,"response_max_bytes":65536,"timeout_ms":5000,"credential_injection":{"location":"header","name":"X-API-Key"},"redaction":{"headers":["X-API-Key"],"query_parameters":[],"response_fields":["email"]}}`
	h.catalogBody = allowJSON(envelopeJSON("http.get", "read", "leads", execUser),
		descriptorJSON("http_api", "opaque_ref", "", "", `[{"name":"http.get","action":"read"}]`, httpBlock), "")
	h.transport.routes["api.example.com"] = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/leads" || r.URL.Query().Get("limit") != "5" || r.Header.Get("X-API-Key") != execCRMKey {
			t.Errorf("http_api request = %s %v", r.URL, r.Header)
		}
		_, _ = io.WriteString(w, `{"records":[{"id":1,"email":"x@example.test"}]}`)
	}
	out, code := h.run("--capability", "http.get", "--action", "read", "--resource", "leads", "--user", execUser, "--input", `{"path":"/leads","query":{"limit":["5"]}}`)
	if code != 0 {
		t.Fatalf("outcome = %d %v (stderr %q)", code, out, h.lastStderr)
	}
	result := out["result"].(map[string]any)
	if result["status_code"].(float64) != 200 || strings.Contains(fmt.Sprint(result["body"]), "x@example.test") {
		t.Fatalf("result = %v", result)
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

// The proxied OAuth token must never be re-emitted by accident: encoding or
// printing the credential (or a response holding it) yields a placeholder.
func TestOAuthCredentialNeverPrintsTheToken(t *testing.T) {
	var resp ConnectorInvokeResponse
	if err := json.Unmarshal([]byte(`{"decision":"allow","oauth":`+oauthJSON(time.Now().Add(time.Minute))+`}`), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.OAuth == nil || resp.OAuth.AccessToken != execToken {
		t.Fatal("token was not decoded")
	}
	encoded, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{string(encoded), fmt.Sprintf("%v %+v %#v %s", *resp.OAuth, resp, *resp.OAuth, *resp.OAuth)} {
		if strings.Contains(text, execToken) {
			t.Fatalf("token leaked: %s", text)
		}
	}
}
