package httpapi

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
)

// fakeHTTPCredentials is a CredentialResolver that returns a canned value. It
// records the reference it was asked to resolve so tests can assert that the
// runtime resolves the opaque reference and never a literal.
type fakeHTTPCredentials struct {
	value string
	err   error
	ref   string
}

func (f *fakeHTTPCredentials) Resolve(_ context.Context, ref string) (string, error) {
	f.ref = ref
	return f.value, f.err
}

// fakeSecretStore is a minimal in-memory SecretStore used to exercise the
// secret-store credential boundary. It never holds real credential material.
type fakeSecretStore struct {
	value string
	err   error
}

func (f *fakeSecretStore) Get(_ context.Context, _, _ string) (*string, error) {
	if f.err != nil {
		return nil, f.err
	}
	v := f.value
	return &v, nil
}
func (f *fakeSecretStore) Put(_ context.Context, _, _, _ string) error { return f.err }
func (f *fakeSecretStore) Delete(_ context.Context, _, _ string) error { return f.err }
func (f *fakeSecretStore) Validate(_ context.Context, _, _ string) error {
	return f.err
}

// httpRuntimeFixture returns valid HTTP API connector metadata pointing at a
// public-looking registered host. The hostname never resolves to a real
// network target in tests; LookupIP is stubbed to a public address.
func httpRuntimeFixture(base string) contract.Metadata {
	return contract.Metadata{
		ID:            "connector-1",
		TenantID:      "tenant-1",
		WorkspaceID:   "workspace-1",
		Name:          "contacts",
		Provider:      contract.ProviderHTTPAPI,
		Status:        contract.StatusActive,
		CredentialRef: "opaque/ref-1",
		Scopes:        []string{"contacts:read"},
		Resources:     []string{"contacts/*"},
		Policy:        contract.PolicyAttributes{AllowedActions: []contract.Action{contract.ActionRead}, AllowedResources: []string{"contacts"}},
		Capabilities:  contract.CapabilitiesFor(contract.ProviderHTTPAPI),
		CreatedBy:     "subject-1",
		HTTPAPI: &contract.HTTPAPI{
			RegisteredBaseURL:   base + "/v1",
			RegisteredHostname:  "api.example.test",
			AllowedMethods:      []contract.HTTPMethod{contract.HTTPMethodGet, contract.HTTPMethodHead},
			AllowedPathPatterns: []string{"/contacts/*"},
			QueryAllowlist:      []string{"limit"},
			RequestMaxBytes:     1024,
			ResponseMaxBytes:    1024,
			TimeoutMS:           100,
			CredentialInjection: contract.CredentialInjection{Location: contract.CredentialInjectionHeader, Name: "X-API-Key"},
			Redaction:           contract.RedactionRules{Headers: []string{"X-API-Key"}, ResponseFields: []string{"access_token"}},
		},
	}
}

func runtimeInvocation() contract.Invocation {
	return contract.Invocation{
		TenantID:    "tenant-1",
		WorkspaceID: "workspace-1",
		Subject:     "subject-1",
		AgentID:     "agent-1",
		ConnectorID: "connector-1",
		Capability:  "http.get",
		Action:      contract.ActionRead,
		Resource:    "contacts/42",
		TraceID:     "trace-1",
		HTTP:        &contract.HTTPInvocation{Method: contract.HTTPMethodGet, Path: "/contacts/42", Query: map[string][]string{"limit": {"10"}}},
	}
}

// mappedClient rewrites every outbound request to the test server while
// preserving the registered hostname in the Host header and in the request URL
// seen by redirect handling. This lets tests exercise real DNS-independent
// flows against httptest servers without binding a real public address.
func mappedClient(server *httptest.Server) *http.Client {
	transport := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		copy := r.Clone(r.Context())
		u := *r.URL
		target := server.URL
		parsed, _ := http.NewRequest(http.MethodGet, target, nil)
		u.Scheme, u.Host = parsed.URL.Scheme, parsed.URL.Host
		copy.URL = &u
		copy.Host = "api.example.test"
		return server.Client().Transport.RoundTrip(copy)
	})
	return &http.Client{Transport: transport}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func publicLookup(context.Context, string) ([]net.IP, error) {
	return []net.IP{net.ParseIP("8.8.8.8")}, nil
}

func TestExecuteHTTPGovernedSuccessInjectsCredentialAndRedacts(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "fixture-credential" {
			t.Errorf("credential header not injected")
		}
		if r.URL.Path != "/v1/contacts/42" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("limit") != "10" {
			t.Errorf("query allowlist not applied: %s", r.URL.RawQuery)
		}
		w.Header().Set("X-API-Key", "fixture-credential")
		_, _ = io.WriteString(w, `{"ok":true,"access_token":"fixture-credential"}`)
	}))
	defer server.Close()

	m := httpRuntimeFixture("https://api.example.test")
	creds := &fakeHTTPCredentials{value: "fixture-credential"}
	result, err := (HTTPExecutor{Credentials: creds, Client: mappedClient(server), LookupIP: publicLookup}).ExecuteHTTP(context.Background(), m, runtimeInvocation())
	if err != nil {
		t.Fatalf("ExecuteHTTP: %v", err)
	}
	if result.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", result.StatusCode)
	}
	if strings.Contains(string(result.Body), "fixture-credential") {
		t.Fatalf("response body leaked credential material: %s", result.Body)
	}
	if result.Headers.Get("X-API-Key") != "[REDACTED]" {
		t.Fatalf("credential header not redacted: %+v", result.Headers)
	}
	if creds.ref != "opaque/ref-1" {
		t.Fatalf("resolver saw ref %q, want opaque/ref-1", creds.ref)
	}
}

func TestExecuteHTTPAuditLineagePreservesFullContext(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer server.Close()

	m := httpRuntimeFixture("https://api.example.test")
	result, err := (HTTPExecutor{Credentials: &fakeHTTPCredentials{value: "secret"}, Client: mappedClient(server), LookupIP: publicLookup}).ExecuteHTTP(context.Background(), m, runtimeInvocation())
	if err != nil {
		t.Fatalf("ExecuteHTTP: %v", err)
	}
	a := result.Audit
	if a.Subject != "subject-1" || a.OrgID != "tenant-1" || a.WorkspaceID != "workspace-1" || a.AgentID != "agent-1" || a.ConnectorID != "connector-1" || a.Capability != "http.get" || a.Action != contract.ActionRead || a.Resource != "contacts/42" || a.TraceID != "trace-1" {
		t.Fatalf("audit lineage not preserved: %+v", a)
	}
}

func TestExecuteHTTPEnforcesMethodPathQuery(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	m := httpRuntimeFixture("https://api.example.test")
	executor := HTTPExecutor{Credentials: &fakeHTTPCredentials{value: "secret"}, Client: mappedClient(server), LookupIP: publicLookup}

	cases := map[string]struct {
		in  contract.Invocation
		key string
	}{
		"disallowed method": {func() contract.Invocation {
			in := runtimeInvocation()
			in.HTTP.Method = "POST"
			return in
		}(), "HTTP method does not match capability"},
		"path outside allowlist": {func() contract.Invocation {
			in := runtimeInvocation()
			in.HTTP.Path = "/users/1"
			return in
		}(), "HTTP path is not allowed"},
		"absolute attacker path": {func() contract.Invocation {
			in := runtimeInvocation()
			in.HTTP.Path = "https://evil.example/x"
			return in
		}(), "HTTP path must be relative"},
		"path traversal": {func() contract.Invocation {
			in := runtimeInvocation()
			in.HTTP.Path = "/contacts/../admin"
			return in
		}(), "HTTP path traversal is not allowed"},
		"query outside allowlist": {func() contract.Invocation {
			in := runtimeInvocation()
			in.HTTP.Query = map[string][]string{"api_key": {"hunter2"}}
			return in
		}(), `query parameter "api_key" is not allowed`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := executor.ExecuteHTTP(context.Background(), m, tc.in); err == nil || !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("error = %v, want containing %q", err, tc.key)
			}
		})
	}
}

func TestExecuteHTTPFailsClosedBeforeRequest(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	base := httpRuntimeFixture("https://api.example.test")

	for name, mutate := range map[string]func(*contract.Metadata){
		"invalid credential ref": func(m *contract.Metadata) { m.CredentialRef = "https://secret.invalid" },
		"disabled":               func(m *contract.Metadata) { m.Status = contract.StatusSuspended },
		"missing capability":     func(m *contract.Metadata) { m.Capabilities = nil },
		"cross-tenant":           func(m *contract.Metadata) { m.TenantID = "other-tenant" },
	} {
		t.Run(name, func(t *testing.T) {
			m := base
			mutate(&m)
			if _, err := (HTTPExecutor{Credentials: &fakeHTTPCredentials{value: "secret"}, Client: mappedClient(server), LookupIP: publicLookup}).ExecuteHTTP(context.Background(), m, runtimeInvocation()); err == nil {
				t.Fatal("unsafe invocation was allowed")
			}
		})
	}

	t.Run("missing resolver", func(t *testing.T) {
		if _, err := (HTTPExecutor{}).ExecuteHTTP(context.Background(), base, runtimeInvocation()); err == nil {
			t.Fatal("missing resolver was allowed")
		}
	})
}

func TestExecuteHTTPRejectsPrivateLinkLocalAndMetadataTargets(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	m := httpRuntimeFixture("https://api.example.test")

	for name, ips := range map[string][]net.IP{
		"loopback":     {net.ParseIP("127.0.0.1")},
		"private":      {net.ParseIP("10.0.0.1")},
		"link-local":   {net.ParseIP("169.254.169.254")},
		"cgNAT":        {net.ParseIP("100.64.0.1")},
		"benchmark":    {net.ParseIP("198.18.0.1")},
		"zero network": {net.ParseIP("0.0.0.1")},
		"mixed public": {net.ParseIP("8.8.8.8"), net.ParseIP("192.168.1.1")},
		"unresolvable": nil,
	} {
		t.Run(name, func(t *testing.T) {
			executor := HTTPExecutor{Credentials: &fakeHTTPCredentials{value: "secret"}, Client: mappedClient(server)}
			executor.LookupIP = func(context.Context, string) ([]net.IP, error) {
				if ips == nil {
					return nil, errors.New("no such host")
				}
				return ips, nil
			}
			_, err := executor.ExecuteHTTP(context.Background(), m, runtimeInvocation())
			if err == nil {
				t.Fatal("reserved target was allowed")
			}
			if name != "unresolvable" && !errors.Is(err, errHTTPReservedTarget) {
				t.Fatalf("error = %v, want errHTTPReservedTarget", err)
			}
		})
	}
}

func TestExecuteHTTPTimeoutOversizeAndRedirectPolicy(t *testing.T) {
	for name, handler := range map[string]http.Handler{
		"timeout":   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(200 * time.Millisecond) }),
		"oversized": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, strings.Repeat("x", 2048)) }),
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewTLSServer(handler)
			defer srv.Close()
			m := httpRuntimeFixture("https://api.example.test")
			if name == "oversized" {
				m.HTTPAPI.TimeoutMS = 1000
			}
			_, err := (HTTPExecutor{Credentials: &fakeHTTPCredentials{value: "secret"}, Client: mappedClient(srv), LookupIP: publicLookup}).ExecuteHTTP(context.Background(), m, runtimeInvocation())
			if err == nil {
				t.Fatal("expected execution failure")
			}
			if name == "oversized" && !errors.Is(err, errHTTPResponseTooLarge) {
				t.Fatalf("error = %v", err)
			}
		})
	}

	t.Run("cross-host redirect denied", func(t *testing.T) {
		redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://other.example.test/v1/contacts/42", http.StatusFound)
		}))
		defer redirect.Close()
		m := httpRuntimeFixture("https://api.example.test")
		m.HTTPAPI.AllowRedirects = true
		m.HTTPAPI.MaxRedirects = 2
		if _, err := (HTTPExecutor{Credentials: &fakeHTTPCredentials{value: "secret"}, Client: mappedClient(redirect), LookupIP: publicLookup}).ExecuteHTTP(context.Background(), m, runtimeInvocation()); err == nil {
			t.Fatal("cross-host redirect was allowed")
		}
	})

	t.Run("redirect disabled returns final 3xx", func(t *testing.T) {
		redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://api.example.test/v1/contacts/42", http.StatusFound)
		}))
		defer redirect.Close()
		m := httpRuntimeFixture("https://api.example.test")
		m.HTTPAPI.AllowRedirects = false
		m.HTTPAPI.MaxRedirects = 0
		result, err := (HTTPExecutor{Credentials: &fakeHTTPCredentials{value: "secret"}, Client: mappedClient(redirect), LookupIP: publicLookup}).ExecuteHTTP(context.Background(), m, runtimeInvocation())
		if err != nil {
			t.Fatalf("ExecuteHTTP: %v", err)
		}
		if result.StatusCode != http.StatusFound {
			t.Fatalf("status = %d, want 302 (redirect not followed)", result.StatusCode)
		}
	})

	t.Run("same-host redirect allowed", func(t *testing.T) {
		redirected := false
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !redirected {
				redirected = true
				http.Redirect(w, r, "https://api.example.test/v1/contacts/43", http.StatusFound)
				return
			}
			_, _ = io.WriteString(w, `{"ok":true}`)
		}))
		defer server.Close()
		m := httpRuntimeFixture("https://api.example.test")
		m.HTTPAPI.AllowRedirects = true
		m.HTTPAPI.MaxRedirects = 2
		result, err := (HTTPExecutor{Credentials: &fakeHTTPCredentials{value: "secret"}, Client: mappedClient(server), LookupIP: publicLookup}).ExecuteHTTP(context.Background(), m, runtimeInvocation())
		if err != nil {
			t.Fatalf("ExecuteHTTP: %v", err)
		}
		if result.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", result.StatusCode)
		}
	})
}

func TestSecretStoreCredentialResolverBoundary(t *testing.T) {
	ctx := context.Background()
	t.Run("resolves via secret store", func(t *testing.T) {
		r := SecretStoreCredentialResolver{Store: &fakeSecretStore{value: "resolved-credential"}, Backend: "vault"}
		got, err := r.Resolve(ctx, "opaque/ref-1")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if got != "resolved-credential" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("rejects inline material before backend I/O", func(t *testing.T) {
		r := SecretStoreCredentialResolver{Store: &fakeSecretStore{value: "resolved-credential"}, Backend: "vault"}
		if _, err := r.Resolve(ctx, "https://secret.invalid"); err == nil {
			t.Fatal("URL reference was accepted")
		}
		if _, err := r.Resolve(ctx, "sk_live_abcdef"); err == nil {
			t.Fatal("inline secret was accepted")
		}
	})
	t.Run("missing store fails closed", func(t *testing.T) {
		r := SecretStoreCredentialResolver{Backend: "vault"}
		if _, err := r.Resolve(ctx, "opaque/ref-1"); err == nil {
			t.Fatal("missing store was accepted")
		}
	})
	t.Run("backend failure is generic", func(t *testing.T) {
		r := SecretStoreCredentialResolver{Store: &fakeSecretStore{err: errors.New("secret store unavailable")}, Backend: "vault"}
		if _, err := r.Resolve(ctx, "opaque/ref-1"); err == nil || strings.Contains(err.Error(), "opaque/ref-1") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestHTTPResponseBodyRedactionDeepAndNonJSON(t *testing.T) {
	body := redactResponseBody([]byte(`{"data":{"access_token":"t1","nested":[{"access_token":"t2"}]},"safe":"x"}`), []string{"access_token"})
	if strings.Contains(string(body), "t1") || strings.Contains(string(body), "t2") || !strings.Contains(string(body), "safe") {
		t.Fatalf("deep redaction failed: %s", body)
	}
	if got := redactResponseBody([]byte("plain text"), []string{"access_token"}); string(got) != "plain text" {
		t.Fatalf("non-JSON body was modified: %s", got)
	}
}
