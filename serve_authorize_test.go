package connectorruntime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const toolAuthorizeTestToken = "kh_live_runtime_test_token_1234567890"

type recordingToolABAC struct {
	requests []AuthorizeRequest
	resp     AuthorizeResponse
	err      error
}

func (f *recordingToolABAC) Authorize(_ context.Context, req AuthorizeRequest) (*AuthorizeResponse, error) {
	f.requests = append(f.requests, req)
	if f.err != nil {
		return nil, f.err
	}
	resp := f.resp
	return &resp, nil
}

type fakeToolCredentialBinding struct{ err error }

func (f fakeToolCredentialBinding) Resolve(context.Context, string, string, string) (*CredentialDescriptor, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &CredentialDescriptor{SecretBackend: "aws-secrets-manager", SecretRef: "kei/github"}, nil
}

type fakeToolSecretStore struct{ value string }

func (f fakeToolSecretStore) Get(context.Context, string, string) (*string, error) {
	return &f.value, nil
}
func (fakeToolSecretStore) Put(context.Context, string, string, string) error { return nil }
func (fakeToolSecretStore) Delete(context.Context, string, string) error      { return nil }
func (fakeToolSecretStore) Validate(context.Context, string, string) error    { return nil }

func newToolAuthorizeHandler(t *testing.T, abac ABACClient) *runtimeHTTPHandler {
	t.Helper()
	return &runtimeHTTPHandler{
		cfg: Config{
			RuntimeControlPlaneURL: "http://control-plane.test",
			RuntimeToken:           toolAuthorizeTestToken,
			RegistryPath:           "tools.yaml",
			AuditPath:              filepath.Join(t.TempDir(), "audit.jsonl"),
		},
		abac:              abac,
		credentialBinding: fakeToolCredentialBinding{},
		secretStore:       fakeToolSecretStore{value: "ghp_secret_value"},
	}
}

// serveToolAuthorize sends the request as if it arrived on the Unix socket.
func serveToolAuthorize(h http.Handler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), unixConnKey{}, true))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeToolAuthorize(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	return body
}

func TestValidateToolName(t *testing.T) {
	for _, name := range []string{
		"github",
		"web_search",
		"github.create_pr",
		"utilities.admin_bonus.list_approval_blockers",
		strings.Repeat("a", 128),
	} {
		if err := validateToolName(name); err != nil {
			t.Errorf("validateToolName(%q) = %v, want nil", name, err)
		}
	}
	for _, name := range []string{
		"",
		"GitHub.create_pr",
		"github-create-pr",
		"github..create_pr",
		".github",
		"github.",
		"github create_pr",
		"github:write",
		strings.Repeat("a", 129),
	} {
		if err := validateToolName(name); err == nil {
			t.Errorf("validateToolName(%q) = nil, want error", name)
		}
	}
}

func TestToolAuthorizeAllowSendsToolAndAudits(t *testing.T) {
	abac := &recordingToolABAC{resp: AuthorizeResponse{Decision: "allow"}}
	h := newToolAuthorizeHandler(t, abac)

	rec := serveToolAuthorize(h, `{"tool":"utilities.admin_bonus.list_approval_blockers","invoking_subject":"alice@example.com","span_id":"span-1","framework":"claude"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if body := decodeToolAuthorize(t, rec); body["decision"] != "allow" {
		t.Fatalf("decision = %v, want allow", body["decision"])
	}
	if len(abac.requests) != 1 {
		t.Fatalf("authorize calls = %d, want 1", len(abac.requests))
	}
	req := abac.requests[0]
	if req.Tool != "utilities.admin_bonus.list_approval_blockers" {
		t.Fatalf("tool = %q", req.Tool)
	}
	if req.Resource != "" || len(req.Resources) != 0 {
		t.Fatalf("resource = %q, resources = %v; want none", req.Resource, req.Resources)
	}
	if req.HarnessToken != toolAuthorizeTestToken {
		t.Fatal("authorize did not use the daemon's runtime token")
	}
	if req.InvokingSubject != "alice@example.com" || req.UserID != "alice@example.com" {
		t.Fatalf("subject = %q, user = %q", req.InvokingSubject, req.UserID)
	}

	data, err := os.ReadFile(h.cfg.AuditPath)
	if err != nil {
		t.Fatal(err)
	}
	var event DecisionEvent
	if err := json.Unmarshal(data, &event); err != nil {
		t.Fatal(err)
	}
	if event.ToolName != "utilities.admin_bonus.list_approval_blockers" || event.InvokingSubject != "alice@example.com" || event.SpanID != "span-1" {
		t.Fatalf("audit event = %+v", event)
	}
}

func TestToolAuthorizeCredentialedServiceNeverReturnsSecret(t *testing.T) {
	abac := &recordingToolABAC{resp: AuthorizeResponse{Decision: "allow"}}
	h := newToolAuthorizeHandler(t, abac)

	rec := serveToolAuthorize(h, `{"tool":"github.create_pr","action":"github:write","invoking_subject":"alice"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "ghp_secret_value") || strings.Contains(rec.Body.String(), "credential") {
		t.Fatalf("response carries secret material: %s", rec.Body.String())
	}
	body := decodeToolAuthorize(t, rec)
	if body["decision"] != "allow" {
		t.Fatalf("decision = %v, want allow", body["decision"])
	}
	req := abac.requests[0]
	if req.Service != "github" || req.Action != "github:write" || req.Resource != "" {
		t.Fatalf("request = %+v, want service github, caller action, no synthesized resource", req)
	}
}

func TestToolAuthorizeCredentialedServiceWithoutBindingIsEnrollmentRequired(t *testing.T) {
	h := newToolAuthorizeHandler(t, &recordingToolABAC{resp: AuthorizeResponse{Decision: "allow"}})
	h.credentialBinding = fakeToolCredentialBinding{err: errCredentialBindingNotFound}

	rec := serveToolAuthorize(h, `{"tool":"github.create_pr","invoking_subject":"alice"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	body := decodeToolAuthorize(t, rec)
	if body["decision"] != "enrollment_required" || body["service"] != "github" {
		t.Fatalf("body = %v, want enrollment_required for github", body)
	}
}

func TestToolAuthorizeDenyPassesReasonAndConnect(t *testing.T) {
	connect := json.RawMessage(`{"url":"https://example.kei.test/connect/gmail"}`)
	h := newToolAuthorizeHandler(t, &recordingToolABAC{resp: AuthorizeResponse{Decision: "deny", Reason: "no matching policy", Connect: &connect}})

	rec := serveToolAuthorize(h, `{"tool":"web_search"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	body := decodeToolAuthorize(t, rec)
	if body["decision"] != "deny" || body["reason"] != "no matching policy" || body["connect"] == nil {
		t.Fatalf("body = %v", body)
	}
}

func TestToolAuthorizeRejectsBadRequestsBeforeCatalog(t *testing.T) {
	for name, payload := range map[string]string{
		"invalid tool":      `{"tool":"Utilities/Admin Bonus"}`,
		"missing tool":      `{"action":"read"}`,
		"too long tool":     `{"tool":"` + strings.Repeat("a", 129) + `"}`,
		"caller resource":   `{"tool":"github.create_pr","resource":"acme/widgets"}`,
		"caller resources":  `{"tool":"github.create_pr","resources":["acme/widgets"]}`,
		"bad subject":       `{"tool":"web_search","invoking_subject":"alice\u0000"}`,
		"negative depth":    `{"tool":"web_search","delegation_depth":-1}`,
		"not a JSON object": `tool=web_search`,
	} {
		t.Run(name, func(t *testing.T) {
			abac := &recordingToolABAC{resp: AuthorizeResponse{Decision: "allow"}}
			rec := serveToolAuthorize(newToolAuthorizeHandler(t, abac), payload)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
			}
			if body := decodeToolAuthorize(t, rec); body["decision"] != "deny" {
				t.Fatalf("decision = %v, want deny", body["decision"])
			}
			if len(abac.requests) != 0 {
				t.Fatalf("catalog called %d times for a rejected request", len(abac.requests))
			}
		})
	}
}

func TestToolAuthorizeNotReadyFailsClosed(t *testing.T) {
	h := &runtimeHTTPHandler{cfg: Config{}, abac: &recordingToolABAC{resp: AuthorizeResponse{Decision: "allow"}}}

	rec := serveToolAuthorize(h, `{"tool":"web_search"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if body := decodeToolAuthorize(t, rec); body["decision"] != "deny" {
		t.Fatalf("decision = %v, want deny", body["decision"])
	}
}

func TestToolAuthorizeCatalogErrorFailsClosed(t *testing.T) {
	h := newToolAuthorizeHandler(t, &recordingToolABAC{err: errors.New("dial tcp: connection refused")})

	rec := serveToolAuthorize(h, `{"tool":"web_search"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if body := decodeToolAuthorize(t, rec); body["decision"] != "deny" {
		t.Fatalf("decision = %v, want deny", body["decision"])
	}
}

func TestToolAuthorizeMissingRegistryFailsClosed(t *testing.T) {
	abac := &recordingToolABAC{resp: AuthorizeResponse{Decision: "allow"}}
	h := newToolAuthorizeHandler(t, abac)
	h.cfg.RegistryPath = filepath.Join(t.TempDir(), "missing.yaml")

	rec := serveToolAuthorize(h, `{"tool":"web_search"}`)
	if rec.Code != http.StatusServiceUnavailable || len(abac.requests) != 0 {
		t.Fatalf("status = %d, catalog calls = %d; want 503 and none", rec.Code, len(abac.requests))
	}
}

// The TCP listener has no owner-only permission check, so it never serves
// tool authorization.
func TestToolAuthorizeIsNotServedOverTCP(t *testing.T) {
	abac := &recordingToolABAC{resp: AuthorizeResponse{Decision: "allow"}}
	h := newToolAuthorizeHandler(t, abac)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(`{"tool":"web_search"}`)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if len(abac.requests) != 0 {
		t.Fatal("catalog called for a TCP request")
	}
}
