package obo

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

const (
	testTenant    = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	otherTenant   = "ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee"
	testClientID  = "11111111-2222-3333-4444-555555555555"
	testResource  = "https://api.example.com"
	testScope     = "https://api.example.com/Data.Read"
	testConnector = "c-obo"
	testSubject   = "user-1"
	userOID       = "99999999-0000-0000-0000-000000000001"
	clientSecret  = "client-secret-canary-7f3a"
	accessCanary  = "access-token-canary-0b1d"
)

// unsignedJWT builds a header.payload.signature token whose payload is
// claims. The exchanger reads claims only; it does not verify signatures.
func unsignedJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + enc.EncodeToString(payload) + ".c2ln"
}

func userAssertion(t *testing.T, tid, oid string) string {
	return unsignedJWT(t, map[string]any{"aud": "api://" + testClientID, "tid": tid, "oid": oid, "exp": time.Now().Add(time.Hour).Unix()})
}

func oboDescriptor(resource string, scopes ...string) policybundle.Connector {
	return policybundle.Connector{
		ID:                testConnector,
		Provider:          string(contract.ProviderHTTPAPI),
		CredentialSource:  string(contract.CredentialSourceOnBehalfOf),
		AccountModel:      string(contract.AccountModelPerUser),
		CredentialBackend: "aws-secrets-manager",
		OnBehalfOf: &contract.OnBehalfOf{
			TenantID:        testTenant,
			ClientID:        testClientID,
			Resource:        resource,
			Scopes:          scopes,
			ClientSecretRef: "kei://connectors/" + testConnector + "/client_secret",
		},
	}
}

type fakeDescriptors struct {
	mu sync.Mutex
	m  map[string]policybundle.Connector
}

func (f *fakeDescriptors) ConnectorDescriptor(id string) (policybundle.Connector, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.m[id]
	return c, ok
}

func (f *fakeDescriptors) set(c policybundle.Connector) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[c.ID] = c
}

// fakeIdentities is the bundle's linked identities by (user id, source).
type fakeIdentities map[[2]string]string

func (f fakeIdentities) LinkedIdentity(userID, source string) (string, bool) {
	id, ok := f[[2]string{userID, source}]
	return id, ok
}

type fakeSecrets struct {
	got policybundle.Connector
}

func (f *fakeSecrets) Resolve(_ context.Context, c policybundle.Connector) (string, error) {
	f.got = c
	return clientSecret, nil
}

// tokenServer is an httptest Entra token endpoint. claims returns the
// exchanged token's claims for one request; the default issues a token that
// passes every check.
type tokenServer struct {
	*httptest.Server
	calls  atomic.Int32
	mu     sync.Mutex
	form   map[string][]string
	path   string
	claims func() map[string]any
	status int
	body   string
}

func newTokenServer(t *testing.T) *tokenServer {
	ts := &tokenServer{status: http.StatusOK}
	ts.claims = func() map[string]any {
		return map[string]any{"aud": testResource, "scp": "Data.Read", "tid": testTenant, "oid": userOID, "exp": time.Now().Add(time.Hour).Unix()}
	}
	ts.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.calls.Add(1)
		_ = r.ParseForm()
		ts.mu.Lock()
		ts.form, ts.path = r.PostForm, r.URL.Path
		ts.mu.Unlock()
		if ts.status != http.StatusOK {
			w.WriteHeader(ts.status)
			_, _ = w.Write([]byte(ts.body))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token_type":   "Bearer",
			"access_token": unsignedJWT(t, ts.claims()),
			"expires_in":   3600,
		})
	}))
	t.Cleanup(ts.Close)
	return ts
}

type rig struct {
	ex      *Exchanger
	ts      *tokenServer
	descs   *fakeDescriptors
	ids     fakeIdentities
	secrets *fakeSecrets
	now     time.Time
	logs    *bytes.Buffer
}

func newRig(t *testing.T) *rig {
	r := &rig{
		ts:      newTokenServer(t),
		descs:   &fakeDescriptors{m: map[string]policybundle.Connector{}},
		ids:     fakeIdentities{},
		secrets: &fakeSecrets{},
		now:     time.Unix(1_800_000_000, 0),
		logs:    &bytes.Buffer{},
	}
	r.descs.set(oboDescriptor(testResource, testScope))
	for _, user := range []string{testSubject, "user-2", "user-3"} {
		r.ids[[2]string{user, IdentitySource}] = userOID
	}
	r.ex = New(Config{
		Descriptors: r.descs,
		Identities:  r.ids,
		Secrets:     r.secrets,
		Client:      r.ts.Client(),
		Authority:   r.ts.URL,
		Now:         func() time.Time { return r.now },
		Logger:      slog.New(slog.NewTextHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	return r
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("err = %v, want *obo.Error with code %s", err, code)
	}
	if e.Code != code {
		t.Fatalf("code = %s (%v), want %s", e.Code, err, code)
	}
}

func TestExchangeReturnsTheExchangedToken(t *testing.T) {
	r := newRig(t)
	assertion := userAssertion(t, testTenant, userOID)
	token, expiry, err := r.ex.Exchange(context.Background(), testSubject, testConnector, assertion)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || !strings.Contains(token, ".") {
		t.Fatalf("token = %q", token)
	}
	if want := r.now.Add(time.Hour); !expiry.Equal(want) {
		t.Fatalf("expiry = %v, want %v", expiry, want)
	}
	if r.ts.path != "/"+testTenant+"/oauth2/v2.0/token" {
		t.Fatalf("token endpoint path = %s", r.ts.path)
	}
	want := map[string]string{
		"grant_type":          "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"requested_token_use": "on_behalf_of",
		"client_id":           testClientID,
		"client_secret":       clientSecret,
		"assertion":           assertion,
		"scope":               testScope,
	}
	for k, v := range want {
		if got := r.ts.form[k]; len(got) != 1 || got[0] != v {
			t.Errorf("form %s = %q, want %q", k, got, v)
		}
	}
	if strings.Contains(strings.Join(r.ts.form["scope"], " "), ".default") {
		t.Errorf("scope requested .default: %q", r.ts.form["scope"])
	}
	if r.secrets.got.CredentialRef != "kei://connectors/"+testConnector+"/client_secret" ||
		r.secrets.got.CredentialSource != string(contract.CredentialSourceOpaqueRef) ||
		r.secrets.got.CredentialBackend != "aws-secrets-manager" {
		t.Errorf("client secret resolved as %+v", r.secrets.got)
	}
}

func TestExchangeFailsClosedOnClaimMismatch(t *testing.T) {
	good := func() map[string]any {
		return map[string]any{"aud": testResource, "scp": "Data.Read", "tid": testTenant, "oid": userOID, "exp": time.Now().Add(time.Hour).Unix()}
	}
	for name, tc := range map[string]struct {
		mutate func(map[string]any)
		code   string
	}{
		"aud is another resource": {func(c map[string]any) { c["aud"] = "https://other.example.com" }, "credential_audience_mismatch"},
		"aud is missing":          {func(c map[string]any) { delete(c, "aud") }, "credential_audience_mismatch"},
		"scp lacks the scope":     {func(c map[string]any) { c["scp"] = "Data.Write" }, "credential_claims_mismatch"},
		"scp is missing":          {func(c map[string]any) { delete(c, "scp") }, "credential_claims_mismatch"},
		"tid is another tenant":   {func(c map[string]any) { c["tid"] = otherTenant }, "credential_claims_mismatch"},
		"oid is another user":     {func(c map[string]any) { c["oid"] = "99999999-0000-0000-0000-000000000002" }, "credential_claims_mismatch"},
		"oid is missing":          {func(c map[string]any) { delete(c, "oid") }, "credential_claims_mismatch"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.ts.claims = func() map[string]any {
				c := good()
				tc.mutate(c)
				return c
			}
			token, _, err := r.ex.Exchange(context.Background(), testSubject, testConnector, userAssertion(t, testTenant, userOID))
			wantCode(t, err, tc.code)
			if token != "" {
				t.Fatalf("token returned on mismatch")
			}
			// A rejected token is not cached: the next call exchanges again.
			_, _, _ = r.ex.Exchange(context.Background(), testSubject, testConnector, userAssertion(t, testTenant, userOID))
			if n := r.ts.calls.Load(); n != 2 {
				t.Fatalf("token endpoint calls = %d, want 2", n)
			}
		})
	}
}

func TestExchangeRejectsAnAssertionFromAnotherTenantWithoutExchanging(t *testing.T) {
	r := newRig(t)
	for name, assertion := range map[string]string{
		"other tenant": userAssertion(t, otherTenant, userOID),
		"no oid":       userAssertion(t, testTenant, ""),
		"not a jwt":    "opaque",
	} {
		_, _, err := r.ex.Exchange(context.Background(), testSubject, testConnector, assertion)
		var e *Error
		if !errors.As(err, &e) || e.Code != "assertion_invalid" {
			t.Errorf("%s: err = %v, want assertion_invalid", name, err)
		}
	}
	if n := r.ts.calls.Load(); n != 0 {
		t.Fatalf("token endpoint calls = %d, want 0", n)
	}
}

func TestExchangeDeniesAnInvalidDescriptorWithoutExchanging(t *testing.T) {
	for name, c := range map[string]func() (policybundle.Connector, bool){
		"unknown connector": func() (policybundle.Connector, bool) { return policybundle.Connector{}, false },
		"opaque_ref connector": func() (policybundle.Connector, bool) {
			c := oboDescriptor(testResource, testScope)
			c.CredentialSource, c.OnBehalfOf = string(contract.CredentialSourceOpaqueRef), nil
			return c, true
		},
		"default scope": func() (policybundle.Connector, bool) {
			return oboDescriptor(testResource, testResource+"/.default"), true
		},
		"no scopes": func() (policybundle.Connector, bool) { return oboDescriptor(testResource), true },
		"tenant is not a guid": func() (policybundle.Connector, bool) {
			c := oboDescriptor(testResource, testScope)
			c.OnBehalfOf.TenantID = "evil.example/../x"
			return c, true
		},
		"no credential backend": func() (policybundle.Connector, bool) {
			c := oboDescriptor(testResource, testScope)
			c.CredentialBackend = ""
			return c, true
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.descs.m = map[string]policybundle.Connector{}
			if d, ok := c(); ok {
				r.descs.set(d)
			}
			_, _, err := r.ex.Exchange(context.Background(), testSubject, testConnector, userAssertion(t, testTenant, userOID))
			wantCode(t, err, "descriptor_invalid")
			if n := r.ts.calls.Load(); n != 0 {
				t.Fatalf("token endpoint calls = %d, want 0", n)
			}
		})
	}
}

func TestExchangeServesACachedTokenUntilItNearsExpiry(t *testing.T) {
	r := newRig(t)
	assertion := userAssertion(t, testTenant, userOID)
	first, exp1, err := r.ex.Exchange(context.Background(), testSubject, testConnector, assertion)
	if err != nil {
		t.Fatal(err)
	}
	r.now = r.now.Add(30 * time.Minute)
	second, exp2, err := r.ex.Exchange(context.Background(), testSubject, testConnector, assertion)
	if err != nil {
		t.Fatal(err)
	}
	if second != first || !exp2.Equal(exp1) {
		t.Fatalf("cache miss: second token differs")
	}
	if n := r.ts.calls.Load(); n != 1 {
		t.Fatalf("token endpoint calls = %d, want 1 (cache hit)", n)
	}

	// Another subject has its own entry.
	if _, _, err := r.ex.Exchange(context.Background(), "user-2", testConnector, assertion); err != nil {
		t.Fatal(err)
	}
	if n := r.ts.calls.Load(); n != 2 {
		t.Fatalf("token endpoint calls = %d, want 2 (per-subject cache)", n)
	}
}

func TestExchangeExchangesAgainWithinTheExpirySkew(t *testing.T) {
	r := newRig(t)
	assertion := userAssertion(t, testTenant, userOID)
	_, exp1, err := r.ex.Exchange(context.Background(), testSubject, testConnector, assertion)
	if err != nil {
		t.Fatal(err)
	}
	r.now = exp1.Add(-DefaultExpirySkew + time.Second)
	_, exp2, err := r.ex.Exchange(context.Background(), testSubject, testConnector, assertion)
	if err != nil {
		t.Fatal(err)
	}
	if n := r.ts.calls.Load(); n != 2 {
		t.Fatalf("token endpoint calls = %d, want 2 (re-exchange within skew)", n)
	}
	if !exp2.After(exp1) {
		t.Fatalf("expiry not renewed: %v then %v", exp1, exp2)
	}
}

func TestExchangePurgesTheConnectorWhenItsResourceChanges(t *testing.T) {
	r := newRig(t)
	assertion := userAssertion(t, testTenant, userOID)
	if _, _, err := r.ex.Exchange(context.Background(), testSubject, testConnector, assertion); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.ex.Exchange(context.Background(), "user-2", testConnector, assertion); err != nil {
		t.Fatal(err)
	}

	const moved = "https://moved.example.com"
	r.descs.set(oboDescriptor(moved, moved+"/Data.Read"))
	r.ts.claims = func() map[string]any {
		return map[string]any{"aud": moved, "scp": "Data.Read", "tid": testTenant, "oid": userOID, "exp": time.Now().Add(time.Hour).Unix()}
	}
	if _, _, err := r.ex.Exchange(context.Background(), testSubject, testConnector, assertion); err != nil {
		t.Fatal(err)
	}
	if n := r.ts.calls.Load(); n != 3 {
		t.Fatalf("token endpoint calls = %d, want 3", n)
	}

	// Moving back does not resurrect tokens minted for the old resource:
	// every entry of the connector, for every subject, was purged.
	r.descs.set(oboDescriptor(testResource, testScope))
	r.ts.claims = func() map[string]any {
		return map[string]any{"aud": testResource, "scp": "Data.Read", "tid": testTenant, "oid": userOID, "exp": time.Now().Add(time.Hour).Unix()}
	}
	if _, _, err := r.ex.Exchange(context.Background(), "user-2", testConnector, assertion); err != nil {
		t.Fatal(err)
	}
	if n := r.ts.calls.Load(); n != 4 {
		t.Fatalf("token endpoint calls = %d, want 4 (old-resource entries purged)", n)
	}
}

func TestExchangePurgesTheConnectorWhenItLeavesTheBundle(t *testing.T) {
	r := newRig(t)
	assertion := userAssertion(t, testTenant, userOID)
	if _, _, err := r.ex.Exchange(context.Background(), testSubject, testConnector, assertion); err != nil {
		t.Fatal(err)
	}
	r.descs.m = map[string]policybundle.Connector{}
	_, _, err := r.ex.Exchange(context.Background(), testSubject, testConnector, assertion)
	wantCode(t, err, "descriptor_invalid")
	r.descs.set(oboDescriptor(testResource, testScope))
	if _, _, err := r.ex.Exchange(context.Background(), testSubject, testConnector, assertion); err != nil {
		t.Fatal(err)
	}
	if n := r.ts.calls.Load(); n != 2 {
		t.Fatalf("token endpoint calls = %d, want 2 (entry purged with the connector)", n)
	}
}

// The default client is SSRF-guarded: a token endpoint on a loopback
// address is never dialed. The client trusts the test server's certificate,
// so only the dial guard stands between it and the endpoint.
func TestExchangeDefaultClientRefusesALoopbackTokenEndpoint(t *testing.T) {
	r := newRig(t)
	r.ex = New(Config{Descriptors: r.descs, Identities: r.ids, Secrets: r.secrets, Authority: r.ts.URL, Now: func() time.Time { return r.now }})
	r.ex.client.Transport.(*http.Transport).TLSClientConfig = r.ts.Client().Transport.(*http.Transport).TLSClientConfig
	_, _, err := r.ex.Exchange(context.Background(), testSubject, testConnector, userAssertion(t, testTenant, userOID))
	wantCode(t, err, "exchange_failed")
	if n := r.ts.calls.Load(); n != 0 {
		t.Fatalf("token endpoint calls = %d, want 0 (SSRF guard)", n)
	}
}

func TestExchangeRefusesANonHTTPSAuthority(t *testing.T) {
	r := newRig(t)
	plain := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { r.ts.calls.Add(1) }))
	t.Cleanup(plain.Close)
	r.ex = New(Config{Descriptors: r.descs, Identities: r.ids, Secrets: r.secrets, Client: plain.Client(), Authority: plain.URL, Now: func() time.Time { return r.now }})
	_, _, err := r.ex.Exchange(context.Background(), testSubject, testConnector, userAssertion(t, testTenant, userOID))
	wantCode(t, err, "exchange_failed")
	if n := r.ts.calls.Load(); n != 0 {
		t.Fatalf("plain-http endpoint calls = %d, want 0", n)
	}
}

// The client secret, the user's assertion and the exchanged token never
// appear in a log line or an error, on success or on any failure, even when
// the token endpoint echoes them back.
func TestExchangeNeverLogsOrReturnsSecrets(t *testing.T) {
	r := newRig(t)
	var global bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&global, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	assertion := userAssertion(t, testTenant, userOID)
	r.ts.claims = func() map[string]any {
		return map[string]any{"aud": testResource, "scp": "Data.Read", "tid": testTenant, "oid": userOID, "exp": time.Now().Add(time.Hour).Unix(), "canary": accessCanary}
	}
	token, _, err := r.ex.Exchange(context.Background(), testSubject, testConnector, assertion)
	if err != nil {
		t.Fatal(err)
	}
	var errs []string
	// The endpoint rejects and echoes the request.
	r.ts.status = http.StatusBadRequest
	r.ts.body = `{"error":"invalid_grant","error_description":"bad ` + clientSecret + " " + assertion + `"}`
	_, _, err = r.ex.Exchange(context.Background(), "user-2", testConnector, assertion)
	wantCode(t, err, "exchange_failed")
	errs = append(errs, err.Error())
	// A claim mismatch on a token carrying the canary.
	r.ts.status = http.StatusOK
	r.ts.claims = func() map[string]any {
		return map[string]any{"aud": "https://other.example.com", "canary": accessCanary}
	}
	_, _, err = r.ex.Exchange(context.Background(), "user-3", testConnector, assertion)
	wantCode(t, err, "credential_audience_mismatch")
	errs = append(errs, err.Error())

	out := r.logs.String() + global.String() + strings.Join(errs, "\n")
	for name, secret := range map[string]string{"client secret": clientSecret, "assertion": assertion, "access token": token, "token canary": accessCanary} {
		if strings.Contains(out, secret) {
			t.Errorf("%s leaked:\n%s", name, out)
		}
	}
}

// HAI-669 (R2), ADR-036 amendment decision 3: the assertion's user must be
// the session subject's own Entra identity, the bundle identity
// {source: "entra", external_id: <oid>} of the subject's user id. On a
// mismatch, or with no such identity, nothing is sent to the token endpoint.
func TestExchangeDeniesAnAssertionForAnotherUserWithoutExchanging(t *testing.T) {
	r := newRig(t)
	r.ids[[2]string{testSubject, IdentitySource}] = "99999999-0000-0000-0000-000000000002"
	_, _, err := r.ex.Exchange(context.Background(), testSubject, testConnector, userAssertion(t, testTenant, userOID))
	wantCode(t, err, "assertion_subject_mismatch")
	if n := r.ts.calls.Load(); n != 0 {
		t.Fatalf("token endpoint calls = %d, want 0", n)
	}
}

func TestExchangeDeniesASubjectWithoutAnEntraIdentityWithoutExchanging(t *testing.T) {
	r := newRig(t)
	delete(r.ids, [2]string{testSubject, IdentitySource})
	r.ids[[2]string{testSubject, "discord"}] = userOID
	_, _, err := r.ex.Exchange(context.Background(), testSubject, testConnector, userAssertion(t, testTenant, userOID))
	wantCode(t, err, "assertion_subject_unlinked")

	// Without an identity source at all, every exchange fails closed too.
	noIDs := New(Config{Descriptors: r.descs, Secrets: r.secrets, Client: r.ts.Client(), Authority: r.ts.URL, Now: func() time.Time { return r.now }})
	_, _, err = noIDs.Exchange(context.Background(), testSubject, testConnector, userAssertion(t, testTenant, userOID))
	wantCode(t, err, "assertion_subject_unlinked")
	if n := r.ts.calls.Load(); n != 0 {
		t.Fatalf("token endpoint calls = %d, want 0", n)
	}
}

// A cached token is never served to a subject whose identity no longer
// matches the assertion.
func TestExchangeChecksTheSubjectBeforeServingTheCache(t *testing.T) {
	r := newRig(t)
	assertion := userAssertion(t, testTenant, userOID)
	if _, _, err := r.ex.Exchange(context.Background(), testSubject, testConnector, assertion); err != nil {
		t.Fatal(err)
	}
	delete(r.ids, [2]string{testSubject, IdentitySource})
	token, _, err := r.ex.Exchange(context.Background(), testSubject, testConnector, assertion)
	wantCode(t, err, "assertion_subject_unlinked")
	if token != "" {
		t.Fatal("cached token served after the identity was unlinked")
	}
}

// CheckAssertion runs every pre-exchange check and sends nothing: the
// connector invoke route calls it when the harness hands over an assertion.
func TestCheckAssertionRunsThePreExchangeChecksOnly(t *testing.T) {
	r := newRig(t)
	if err := r.ex.CheckAssertion(testSubject, testConnector, userAssertion(t, testTenant, userOID)); err != nil {
		t.Fatalf("matching assertion rejected: %v", err)
	}
	wantCode(t, r.ex.CheckAssertion(testSubject, testConnector, userAssertion(t, otherTenant, userOID)), "assertion_invalid")
	wantCode(t, r.ex.CheckAssertion("user-9", testConnector, userAssertion(t, testTenant, userOID)), "assertion_subject_unlinked")
	wantCode(t, r.ex.CheckAssertion(testSubject, "c-absent", userAssertion(t, testTenant, userOID)), "descriptor_invalid")
	if n := r.ts.calls.Load(); n != 0 {
		t.Fatalf("token endpoint calls = %d, want 0", n)
	}
}
