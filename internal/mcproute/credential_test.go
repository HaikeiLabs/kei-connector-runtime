package mcproute

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// ADR-036 §4.5 step 10 and §4.8: the route resolves the session's credential
// for the connector and its canonical resource (the descriptor's mcp.url),
// and attaches it upstream only when the released audience is that resource.

const connectorToken = "ct_connector_token_for_test_488"

type fakeCredentials struct {
	mu        sync.Mutex
	cred      ConnectorCredential
	err       error
	asked     []string // session|connector|resource
	discarded []string
}

func (f *fakeCredentials) UseCredential(_ context.Context, sess *Session, connectorID, resource string, fn func(ConnectorCredential) error) error {
	f.mu.Lock()
	f.asked = append(f.asked, sess.SessionID+"|"+connectorID+"|"+resource)
	cred, err := f.cred, f.err
	f.mu.Unlock()
	if err != nil {
		return err
	}
	return fn(cred)
}

func (f *fakeCredentials) Discard(sess *Session, connectorID, resource string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.discarded = append(f.discarded, sess.SessionID+"|"+connectorID+"|"+resource)
}

// credentialRig is a handler for one mcp connector with authMethod whose
// upstream answers tools/call with onCall (an empty result when nil).
func credentialRig(t *testing.T, creds *fakeCredentials, authMethod string, onCall http.HandlerFunc) (*Handler, string, *listingUpstream) {
	t.Helper()
	tool := namedTool("search")
	up := newListingUpstream(t, tool)
	up.onCall = onCall
	cat := catalogFor(up.srv.URL, approvedTools(t, tool))
	cat.connectors[0].MCP.AuthMethod = authMethod
	reg, key := testKey(t)
	h := NewHandler(Config{KeyRegistry: reg, Authorizer: verdictAuthorizer{}, Catalog: cat, Credentials: creds})
	h.checkSSRF = func(*url.URL) error { return nil }
	h.dialCtl = func(string, string, syscall.RawConn) error { return nil }
	return h, key, up
}

// authHeaders are the Authorization headers the upstream saw.
func authHeaders(up *listingUpstream) []string {
	up.mu.Lock()
	defer up.mu.Unlock()
	var out []string
	for _, h := range up.seen {
		out = append(out, h.Get("Authorization"))
	}
	return out
}

func goodCredential(resource string) ConnectorCredential {
	return ConnectorCredential{ConnectorID: "conn-1", Issuer: "https://auth.example.com", Resource: resource, AccountModel: "per_user", AccessToken: connectorToken}
}

func TestMCPRouteCredential_AttachesTheConnectorsToken(t *testing.T) {
	creds := &fakeCredentials{}
	h, key, up := credentialRig(t, creds, "oauth", nil)
	creds.cred = goodCredential(up.srv.URL)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callBody("search")))

	if up.calls.Load() != 1 {
		t.Fatalf("call not forwarded: %s", w.Body.Bytes())
	}
	for i, a := range authHeaders(up) {
		if a != "Bearer "+connectorToken {
			t.Fatalf("upstream request %d Authorization = %q, want the connector token", i, a)
		}
	}
	if len(creds.asked) == 0 || creds.asked[0] != "test-session|conn-1|"+up.srv.URL {
		t.Fatalf("credential asked for %v, want the session, connector and its mcp.url", creds.asked)
	}
	if strings.Contains(w.Body.String(), connectorToken) {
		t.Fatal("the connector token reached the harness")
	}
}

func TestMCPRouteCredential_Denials(t *testing.T) {
	for name, tc := range map[string]struct {
		cred   func(resource string) ConnectorCredential
		err    error
		reason string
	}{
		"released for another resource": {cred: func(string) ConnectorCredential { return goodCredential("https://other.example.com/mcp") }, reason: "credential_audience_mismatch"},
		"released for another connector": {cred: func(r string) ConnectorCredential {
			c := goodCredential(r)
			c.ConnectorID = "conn-other"
			return c
		}, reason: "credential_audience_mismatch"},
		"bridge AUDIENCE_MISMATCH": {err: &CredentialDenied{Reason: "AUDIENCE_MISMATCH"}, reason: "credential_audience_mismatch"},
		"bridge NOT_CONNECTED":     {err: &CredentialDenied{Reason: "NOT_CONNECTED"}, reason: "credential_unavailable"},
		"no session credentials":   {err: &CredentialDenied{Reason: "NO_SESSION"}, reason: "credential_unavailable"},
	} {
		t.Run(name, func(t *testing.T) {
			creds := &fakeCredentials{err: tc.err}
			h, key, up := credentialRig(t, creds, "oauth", nil)
			if tc.cred != nil {
				creds.cred = tc.cred(up.srv.URL)
			}

			w := httptest.NewRecorder()
			h.ServeHTTP(w, routeRequest(key, callBody("search")))

			assertDenied(t, w, -31424, tc.reason)
			if up.lists.Load()+up.calls.Load() != 0 {
				t.Fatalf("the upstream was reached without a usable credential (lists %d calls %d)", up.lists.Load(), up.calls.Load())
			}
		})
	}
}

func TestMCPRouteCredential_NoCredentialSourceIsUnavailable(t *testing.T) {
	h, key, up := credentialRig(t, nil, "oauth", nil)
	h.config.Credentials = nil // not a typed nil

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callBody("search")))

	assertDenied(t, w, -31424, "credential_unavailable")
	if up.lists.Load()+up.calls.Load() != 0 {
		t.Fatal("the upstream was reached without a credential source")
	}
}

func TestMCPRouteCredential_AuthMethodNoneSendsNoCredential(t *testing.T) {
	creds := &fakeCredentials{}
	h, key, up := credentialRig(t, creds, "none", nil)

	h.ServeHTTP(httptest.NewRecorder(), routeRequest(key, callBody("search")))

	if up.calls.Load() != 1 || len(creds.asked) != 0 {
		t.Fatalf("calls %d, credential asked %v: want a forwarded call and no credential", up.calls.Load(), creds.asked)
	}
	for _, a := range authHeaders(up) {
		if a != "" {
			t.Fatalf("Authorization %q sent for auth_method none", a)
		}
	}
}

func TestMCPRouteCredential_SecretRefIsNotSupportedYet(t *testing.T) {
	creds := &fakeCredentials{}
	h, key, up := credentialRig(t, creds, "secret_ref", nil)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callBody("search")))

	assertDenied(t, w, -31424, "credential_unavailable")
	if up.lists.Load()+up.calls.Load() != 0 {
		t.Fatal("a secret_ref connector was dialed")
	}
}

func TestMCPRouteCredential_Upstream401RejectsAndDiscards(t *testing.T) {
	creds := &fakeCredentials{}
	h, key, up := credentialRig(t, creds, "oauth", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	creds.cred = goodCredential(up.srv.URL)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callBody("search")))

	assertDenied(t, w, -31424, "credential_rejected")
	if len(creds.discarded) != 1 || creds.discarded[0] != "test-session|conn-1|"+up.srv.URL {
		t.Fatalf("discarded %v, want the rejected credential dropped", creds.discarded)
	}
}

func TestMCPRouteCredential_InsufficientScopeIsAuditedWithTheChallenge(t *testing.T) {
	creds := &fakeCredentials{}
	aud := &recordingAuditor{}
	h, key, up := credentialRig(t, creds, "oauth", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="dashboards:read dashboards:write", resource_metadata="https://mcp.example/.well-known/oauth-protected-resource"`)
		w.WriteHeader(http.StatusForbidden)
	})
	creds.cred = goodCredential(up.srv.URL)
	h.config.Auditor = aud

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callBody("search")))

	assertDenied(t, w, -31424, "insufficient_scope")
	if rec := aud.only(t); rec.ChallengedScope != "dashboards:read dashboards:write" || rec.ReasonCode != "insufficient_scope" {
		t.Fatalf("audit record %+v, want the challenged scope", rec)
	}
	if len(creds.discarded) != 0 {
		t.Fatal("an insufficient_scope answer must not discard the credential")
	}
}
