package composio

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// fixtureAPIKey is a placeholder, never a real Composio key. Tests assert it
// never leaks into results, audit records, or errors.
const fixtureAPIKey = "fixture-composio-key-not-real"

type fakeCredentials struct {
	ref   string
	value string
	err   error
}

func (f *fakeCredentials) Resolve(_ context.Context, ref string) (string, error) {
	f.ref = ref
	return f.value, f.err
}

type fakeAuthorizer struct {
	decision Decision
	err      error
	calls    int
	got      AuthorizeRequest
}

func (f *fakeAuthorizer) Authorize(_ context.Context, in AuthorizeRequest) (Decision, error) {
	f.calls++
	f.got = in
	return f.decision, f.err
}

func allow() *fakeAuthorizer { return &fakeAuthorizer{decision: Decision{Decision: "allow"}} }

// composioFixture is an httptest stand-in for backend.composio.dev. It serves a
// canned response file and records every request it receives.
type composioFixture struct {
	srv      *httptest.Server
	hits     atomic.Int32
	lastPath string
	lastKey  string
	lastBody map[string]any
}

func newComposioFixture(t *testing.T, status int, file string, headers map[string]string) *composioFixture {
	t.Helper()
	body := readFixture(t, file)
	f := &composioFixture{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		f.lastPath = r.Method + " " + r.URL.Path
		f.lastKey = r.Header.Get("x-api-key")
		raw, _ := io.ReadAll(r.Body)
		f.lastBody = map[string]any{}
		_ = json.Unmarshal(raw, &f.lastBody)
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

func fixtureConfig(t *testing.T) Config {
	t.Helper()
	cfg, err := LoadConfig(filepath.Join("testdata", "config.json"))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	return cfg
}

func executorFor(t *testing.T, f *composioFixture) Executor {
	t.Helper()
	return Executor{
		Config:      fixtureConfig(t),
		Credentials: &fakeCredentials{value: fixtureAPIKey},
		Client:      f.srv.Client(),
		BaseURL:     f.srv.URL,
	}
}

const (
	readCap  = "composio.github.get_a_repository"
	writeCap = "composio.github.star_a_repository_for_the_authenticated_user"
)

func readInvocation() Invocation {
	return Invocation{
		Subject:    "user-member-0001",
		Capability: readCap,
		Action:     "read",
		Resource:   "github/repos/acme/widgets",
		TraceID:    "trace-0001",
		Arguments:  json.RawMessage(`{"owner":"acme","repo":"widgets"}`),
	}
}

func TestGovernedInvokeDenyNeverReachesComposio(t *testing.T) {
	f := newComposioFixture(t, http.StatusOK, "execute_success.json", nil)
	auth := &fakeAuthorizer{decision: Decision{Decision: "deny", Reason: "no matching policy"}}

	_, err := GovernedInvoke(context.Background(), auth, executorFor(t, f), readInvocation())

	if !errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v, want ErrDenied", err)
	}
	if auth.calls != 1 {
		t.Fatalf("authorize calls = %d, want 1", auth.calls)
	}
	if f.hits.Load() != 0 {
		t.Fatalf("composio received %d requests after a deny", f.hits.Load())
	}
}

func TestGovernedInvokeAuthorizeErrorFailsClosed(t *testing.T) {
	f := newComposioFixture(t, http.StatusOK, "execute_success.json", nil)
	auth := &fakeAuthorizer{err: errors.New("control plane unreachable")}

	_, err := GovernedInvoke(context.Background(), auth, executorFor(t, f), readInvocation())

	if !errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v, want ErrDenied", err)
	}
	if f.hits.Load() != 0 {
		t.Fatalf("composio received %d requests after an authorize error", f.hits.Load())
	}
}

func TestGovernedInvokeUnknownDecisionFailsClosed(t *testing.T) {
	f := newComposioFixture(t, http.StatusOK, "execute_success.json", nil)
	auth := &fakeAuthorizer{decision: Decision{Decision: "enrollment_required"}}

	_, err := GovernedInvoke(context.Background(), auth, executorFor(t, f), readInvocation())

	if !errors.Is(err, ErrDenied) || f.hits.Load() != 0 {
		t.Fatalf("err = %v, hits = %d; want ErrDenied and no composio call", err, f.hits.Load())
	}
}

func TestGovernedInvokeAllowExecutesPinnedTool(t *testing.T) {
	f := newComposioFixture(t, http.StatusOK, "execute_success.json", nil)
	creds := &fakeCredentials{value: fixtureAPIKey}
	exec := executorFor(t, f)
	exec.Credentials = creds
	auth := allow()

	res, err := GovernedInvoke(context.Background(), auth, exec, readInvocation())
	if err != nil {
		t.Fatalf("GovernedInvoke: %v", err)
	}

	if f.lastPath != "POST /api/v3.1/tools/execute/GITHUB_GET_A_REPOSITORY" {
		t.Fatalf("path = %q", f.lastPath)
	}
	if f.lastKey != fixtureAPIKey {
		t.Fatalf("x-api-key header not set from the resolved secret")
	}
	if creds.ref != "kei/composio/project-api-key" {
		t.Fatalf("resolved ref = %q, want the configured opaque ref", creds.ref)
	}
	if got := f.lastBody["version"]; got != "20250909_00" {
		t.Fatalf("version = %v, want pinned 20250909_00", got)
	}
	if got := f.lastBody["user_id"]; got != "kei-ws-fixture-0001-user-member-0001" {
		t.Fatalf("user_id = %v, want the configured mapping for the Kei subject", got)
	}
	args, _ := f.lastBody["arguments"].(map[string]any)
	if args["owner"] != "acme" || args["repo"] != "widgets" {
		t.Fatalf("arguments = %v", f.lastBody["arguments"])
	}
	if !res.Successful || res.LogID != "log_fixture_0001" {
		t.Fatalf("result = %+v", res)
	}
	// The authorizer sees the Kei capability, never the Composio slug or key.
	if auth.got.Capability != readCap {
		t.Fatalf("authorize capability = %q", auth.got.Capability)
	}
	// Kei gets a digest of the input, never the input (execution contract §2).
	if auth.got.InputDigest != canonicalDigest(t, `{"owner":"acme","repo":"widgets"}`) {
		t.Fatalf("authorize input_digest = %q", auth.got.InputDigest)
	}
	sent, _ := json.Marshal(auth.got)
	if strings.Contains(string(sent), `"owner":"acme"`) {
		t.Fatalf("authorize request carries the raw input: %s", sent)
	}
}

func TestExecuteRedactsConfiguredFields(t *testing.T) {
	f := newComposioFixture(t, http.StatusOK, "execute_success.json", nil)

	res, err := GovernedInvoke(context.Background(), allow(), executorFor(t, f), readInvocation())
	if err != nil {
		t.Fatalf("GovernedInvoke: %v", err)
	}
	if strings.Contains(string(res.Data), "owner@example.test") {
		t.Fatalf("redacted field leaked: %s", res.Data)
	}
	if !strings.Contains(string(res.Data), "[REDACTED]") || !strings.Contains(string(res.Data), "acme/widgets") {
		t.Fatalf("data = %s", res.Data)
	}
}

func TestExecuteRejectsCapabilityOutsideAllowList(t *testing.T) {
	f := newComposioFixture(t, http.StatusOK, "execute_success.json", nil)
	in := readInvocation()
	in.Capability = "composio.github.delete_a_repository"

	_, err := GovernedInvoke(context.Background(), allow(), executorFor(t, f), in)

	if !errors.Is(err, ErrToolNotAllowed) || f.hits.Load() != 0 {
		t.Fatalf("err = %v, hits = %d; want ErrToolNotAllowed and no composio call", err, f.hits.Load())
	}
}

func TestExecuteRejectsActionMismatch(t *testing.T) {
	f := newComposioFixture(t, http.StatusOK, "execute_success.json", nil)
	in := readInvocation()
	in.Capability = writeCap
	in.Action = "read"

	_, err := GovernedInvoke(context.Background(), allow(), executorFor(t, f), in)

	if !errors.Is(err, ErrActionMismatch) || f.hits.Load() != 0 {
		t.Fatalf("err = %v, hits = %d; want ErrActionMismatch", err, f.hits.Load())
	}
}

func TestExecuteWriteRequiresApproval(t *testing.T) {
	f := newComposioFixture(t, http.StatusOK, "execute_success.json", nil)
	in := readInvocation()
	in.Capability = writeCap
	in.Action = "create"

	_, err := GovernedInvoke(context.Background(), allow(), executorFor(t, f), in)
	if !errors.Is(err, ErrApprovalRequired) || f.hits.Load() != 0 {
		t.Fatalf("err = %v, hits = %d; want ErrApprovalRequired", err, f.hits.Load())
	}

	in.ApprovalID = "approval-0001"
	res, err := GovernedInvoke(context.Background(), allow(), executorFor(t, f), in)
	if err != nil {
		t.Fatalf("approved write: %v", err)
	}
	if res.Audit.ApprovalID != "approval-0001" {
		t.Fatalf("audit approval = %q", res.Audit.ApprovalID)
	}
}

func TestExecuteRejectsUnmappedSubject(t *testing.T) {
	f := newComposioFixture(t, http.StatusOK, "execute_success.json", nil)
	in := readInvocation()
	in.Subject = "user-unlinked-0001"

	_, err := GovernedInvoke(context.Background(), allow(), executorFor(t, f), in)

	if !errors.Is(err, ErrSubjectNotMapped) || f.hits.Load() != 0 {
		t.Fatalf("err = %v, hits = %d; want ErrSubjectNotMapped", err, f.hits.Load())
	}
}

func TestExecuteDisabledByDefault(t *testing.T) {
	f := newComposioFixture(t, http.StatusOK, "execute_success.json", nil)
	exec := executorFor(t, f)
	exec.Config.Enabled = false

	_, err := GovernedInvoke(context.Background(), allow(), exec, readInvocation())

	if !errors.Is(err, ErrDisabled) || f.hits.Load() != 0 {
		t.Fatalf("err = %v, hits = %d; want ErrDisabled", err, f.hits.Load())
	}
}

func TestExecuteCapsResponseSize(t *testing.T) {
	f := newComposioFixture(t, http.StatusOK, "execute_success.json", nil)
	exec := executorFor(t, f)
	exec.Config.ResponseMaxBytes = 16

	_, err := GovernedInvoke(context.Background(), allow(), exec, readInvocation())

	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("err = %v, want ErrResponseTooLarge", err)
	}
}

func TestExecuteUnsuccessfulToolResult(t *testing.T) {
	f := newComposioFixture(t, http.StatusOK, "execute_tool_failed.json", nil)

	res, err := GovernedInvoke(context.Background(), allow(), executorFor(t, f), readInvocation())

	if !errors.Is(err, ErrToolFailed) {
		t.Fatalf("err = %v, want ErrToolFailed", err)
	}
	if strings.Contains(err.Error(), "acme/missing") {
		t.Fatalf("provider error text leaked into the error: %v", err)
	}
	// The audit lineage survives a provider failure so it can be shipped.
	if res == nil || res.Audit.Outcome != "tool_failed" || res.Audit.ComposioLogID != "log_fixture_0002" {
		t.Fatalf("result = %+v", res)
	}
}

func TestExecuteClassifiesHTTPErrors(t *testing.T) {
	cases := []struct {
		status  int
		file    string
		headers map[string]string
		want    error
	}{
		{http.StatusUnauthorized, "error_no_connected_account.json", nil, ErrCredentialsRejected},
		{http.StatusForbidden, "error_no_connected_account.json", nil, ErrCredentialsRejected},
		{http.StatusBadRequest, "error_no_connected_account.json", nil, ErrRequestRejected},
		{http.StatusNotFound, "error_no_connected_account.json", nil, ErrNotFound},
		{http.StatusTooManyRequests, "error_rate_limited.json", map[string]string{"Retry-After": "17"}, ErrRateLimited},
		{http.StatusBadGateway, "error_no_connected_account.json", nil, ErrUnavailable},
	}
	for _, tc := range cases {
		f := newComposioFixture(t, tc.status, tc.file, tc.headers)
		res, err := GovernedInvoke(context.Background(), allow(), executorFor(t, f), readInvocation())
		if !errors.Is(err, tc.want) {
			t.Errorf("status %d: err = %v, want %v", tc.status, err, tc.want)
			continue
		}
		if f.hits.Load() != 1 {
			t.Errorf("status %d: hits = %d, want exactly 1 (no retries)", tc.status, f.hits.Load())
		}
		msg := err.Error()
		if strings.Contains(msg, fixtureAPIKey) || strings.Contains(msg, "No connected account") {
			t.Errorf("status %d: error echoes key or provider body: %v", tc.status, err)
		}
		if tc.status == http.StatusTooManyRequests && (res == nil || res.RetryAfterSeconds != 17) {
			t.Errorf("429: result = %+v, want RetryAfterSeconds 17", res)
		}
	}
}

func TestAuditCarriesLineageButNoSecretsOrRawArgs(t *testing.T) {
	f := newComposioFixture(t, http.StatusOK, "execute_success.json", nil)
	in := readInvocation()

	res, err := GovernedInvoke(context.Background(), allow(), executorFor(t, f), in)
	if err != nil {
		t.Fatalf("GovernedInvoke: %v", err)
	}
	a := res.Audit
	if a.Subject != "user-member-0001" || a.Capability != readCap || a.ToolSlug != "GITHUB_GET_A_REPOSITORY" ||
		a.ToolVersion != "20250909_00" || a.Action != "read" || a.TraceID != "trace-0001" ||
		a.Resource != "github/repos/acme/widgets" || a.ComposioLogID != "log_fixture_0001" ||
		a.Outcome != "success" || a.CredentialClass != "third-party-managed" ||
		a.InputDigest != canonicalDigest(t, `{"repo":"widgets","owner":"acme"}`) {
		t.Fatalf("audit = %+v", a)
	}
	raw, _ := json.Marshal(a)
	for _, leak := range []string{fixtureAPIKey, `"repo":"widgets"`, "owner@example.test", "kei/composio/project-api-key"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("audit leaks %q: %s", leak, raw)
		}
	}
}

func TestCredentialResolutionFailureFailsClosed(t *testing.T) {
	f := newComposioFixture(t, http.StatusOK, "execute_success.json", nil)
	exec := executorFor(t, f)
	exec.Credentials = &fakeCredentials{err: errors.New("vault sealed: kei/composio/project-api-key")}

	_, err := GovernedInvoke(context.Background(), allow(), exec, readInvocation())

	if !errors.Is(err, ErrCredentialUnavailable) || f.hits.Load() != 0 {
		t.Fatalf("err = %v, hits = %d; want ErrCredentialUnavailable", err, f.hits.Load())
	}
	if strings.Contains(err.Error(), "project-api-key") {
		t.Fatalf("error echoes the secret ref: %v", err)
	}
}

func TestConfigValidate(t *testing.T) {
	base := func() Config { return fixtureConfig(t) }
	cases := map[string]func(*Config){
		"latest version": func(c *Config) {
			c.Tools[readCap] = Tool{Slug: "GITHUB_GET_A_REPOSITORY", Version: "latest", Action: "read"}
		},
		"empty version":          func(c *Config) { c.Tools[readCap] = Tool{Slug: "GITHUB_GET_A_REPOSITORY", Action: "read"} },
		"bad capability name":    func(c *Config) { c.Tools["github.get_a_repository"] = c.Tools[readCap] },
		"capability/slug differ": func(c *Config) { c.Tools["composio.slack.get_a_repository"] = c.Tools[readCap] },
		"unknown action": func(c *Config) {
			c.Tools[readCap] = Tool{Slug: "GITHUB_GET_A_REPOSITORY", Version: "20250909_00", Action: "admin"}
		},
		"inline api key":         func(c *Config) { c.APIKeyRef = "Bearer abc123" },
		"missing api key ref":    func(c *Config) { c.APIKeyRef = "" },
		"wrong credential label": func(c *Config) { c.CredentialLabel = "first-party" },
		"no size cap":            func(c *Config) { c.ResponseMaxBytes = 0 },
		"size cap over limit":    func(c *Config) { c.ResponseMaxBytes = MaxResponseBytes + 1 },
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("fixture config invalid: %v", err)
	}
	for name, mutate := range cases {
		c := base()
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: Validate() = nil, want error", name)
		}
	}
}

func TestLoadConfigDefaultsToDisabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "composio.json")
	if err := os.WriteFile(path, []byte(`{"api_key_ref":"kei/composio/key","credential_label":"third-party-managed","response_max_bytes":1024,"tools":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Enabled {
		t.Fatal("composio connector must be default-off")
	}
}

func TestCapabilityName(t *testing.T) {
	cases := []struct{ toolkit, slug, want string }{
		{"github", "GITHUB_GET_A_REPOSITORY", "composio.github.get_a_repository"},
		{"GMAIL", "GMAIL_FETCH_EMAILS", "composio.gmail.fetch_emails"},
		{"googlecalendar", "GOOGLECALENDAR_LIST_EVENTS", "composio.googlecalendar.list_events"},
	}
	for _, tc := range cases {
		got, err := CapabilityName(tc.toolkit, tc.slug)
		if err != nil || got != tc.want {
			t.Errorf("CapabilityName(%q, %q) = %q, %v; want %q", tc.toolkit, tc.slug, got, err, tc.want)
		}
	}
	if _, err := CapabilityName("slack", "GITHUB_GET_A_REPOSITORY"); err == nil {
		t.Error("slug outside its toolkit must be rejected")
	}
}

func TestReasonCodeMatchesExecutionContractVocabulary(t *testing.T) {
	cases := map[error]string{
		ErrDisabled:                 "provider_not_supported",
		ErrDenied:                   "policy_deny",
		ErrInvalidInvocation:        "input_invalid",
		ErrToolNotAllowed:           "policy_deny",
		ErrActionMismatch:           "input_invalid",
		ErrApprovalRequired:         "approval_required",
		ErrSubjectNotMapped:         "oauth_not_connected",
		ErrCredentialUnavailable:    "credential_unavailable",
		ErrCredentialsRejected:      "provider_denied",
		ErrRequestRejected:          "provider_error",
		ErrRateLimited:              "provider_rate_limited",
		ErrUnavailable:              "provider_error",
		ErrTimeout:                  "provider_timeout",
		ErrResponseTooLarge:         "result_too_large",
		ErrToolFailed:               "provider_error",
		errors.New("anything else"): "provider_error",
	}
	for err, want := range cases {
		if got := ReasonCode(err); got != want {
			t.Errorf("ReasonCode(%v) = %q, want %q", err, got, want)
		}
	}
}

func TestExecuteTimeoutIsClassified(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	exec := Executor{Config: fixtureConfig(t), Credentials: &fakeCredentials{value: fixtureAPIKey}, Client: srv.Client(), BaseURL: srv.URL}
	exec.Config.TimeoutMS = 50

	res, err := GovernedInvoke(context.Background(), allow(), exec, readInvocation())

	if !errors.Is(err, ErrTimeout) || res == nil || res.Audit.Outcome != "timeout" {
		t.Fatalf("err = %v, res = %+v; want ErrTimeout", err, res)
	}
}

func TestAuditDigestsResult(t *testing.T) {
	f := newComposioFixture(t, http.StatusOK, "execute_success.json", nil)

	res, err := GovernedInvoke(context.Background(), allow(), executorFor(t, f), readInvocation())
	if err != nil {
		t.Fatalf("GovernedInvoke: %v", err)
	}
	sum := sha256.Sum256(res.Data)
	if res.Audit.ResultDigest != "sha256:"+hex.EncodeToString(sum[:]) || res.Audit.ResultBytes != len(res.Data) {
		t.Fatalf("audit = %+v", res.Audit)
	}
	raw, _ := json.Marshal(res.Audit)
	for _, key := range []string{`"input_digest"`, `"result_digest"`, `"result_bytes"`} {
		if !strings.Contains(string(raw), key) {
			t.Fatalf("audit JSON missing %s: %s", key, raw)
		}
	}
}

// canonicalDigest is the execution contract's input_digest: "sha256:" plus the
// hex SHA-256 of the canonical (sorted-key, compact) JSON of the input.
func canonicalDigest(t *testing.T, input string) string {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(input), &v); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestInputOverContractLimitIsRejected(t *testing.T) {
	f := newComposioFixture(t, http.StatusOK, "execute_success.json", nil)
	in := readInvocation()
	in.Arguments = json.RawMessage(`{"q":"` + strings.Repeat("a", MaxInputBytes) + `"}`)
	auth := allow()

	_, err := GovernedInvoke(context.Background(), auth, executorFor(t, f), in)

	if !errors.Is(err, ErrInvalidInvocation) || auth.calls != 0 || f.hits.Load() != 0 {
		t.Fatalf("err = %v, authorize calls = %d, hits = %d; want input_invalid before any I/O", err, auth.calls, f.hits.Load())
	}
}

func TestNonObjectInputIsRejectedBeforeAuthorize(t *testing.T) {
	f := newComposioFixture(t, http.StatusOK, "execute_success.json", nil)
	in := readInvocation()
	in.Arguments = json.RawMessage(`["not","an","object"]`)
	auth := allow()

	_, err := GovernedInvoke(context.Background(), auth, executorFor(t, f), in)

	if !errors.Is(err, ErrInvalidInvocation) || auth.calls != 0 || f.hits.Load() != 0 {
		t.Fatalf("err = %v, authorize calls = %d, hits = %d", err, auth.calls, f.hits.Load())
	}
}
