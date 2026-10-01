package connectorruntime

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

func TestSyncPolicyBundleAcceptsUnsignedJSONWithRuntimeTokenAndDigest(t *testing.T) {
	now := time.Now().UTC()
	raw := unsignedExampleBundle(t, now)
	digest := fmt.Sprintf(`"sha256:%x"`, sha256.Sum256(raw))
	paths := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths[r.URL.Path]++
		if r.Header.Get("Authorization") != "Bearer kh_live_runtime_test_token_1234567890" {
			t.Errorf("authorization header missing")
		}
		switch r.URL.Path {
		case "/api/v1/runtime/policy-bundles/current":
			if r.Header.Get("Accept") != policybundle.ContentType {
				t.Errorf("Accept=%q", r.Header.Get("Accept"))
			}
			w.Header().Set("Content-Type", policybundle.ContentType)
			w.Header().Set("ETag", digest)
			w.Header().Set("Kei-Policy-Bundle-Version", "42")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write(raw)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	stateDir := t.TempDir()
	cfg := Config{RuntimeToken: "kh_live_runtime_test_token_1234567890", RuntimeControlPlaneURL: server.URL, RuntimeStateDir: stateDir}
	identity := &RuntimeIdentity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001"), Status: "active", BindingStatus: "verified"}
	if err := syncPolicyBundle(context.Background(), cfg, identity, time.Second); err != nil {
		t.Fatal(err)
	}
	store, err := policybundle.OpenStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	bundle, state, err := store.Check(identity.ID, identity.OrgID, *identity.WorkspaceID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if bundle == nil || state != policybundle.Active || bundle.Payload.BundleVersion != 42 || bundle.Digest != strings.Trim(digest, `"`) {
		t.Fatalf("bundle=%v state=%s digest=%s", bundle, state, bundle.Digest)
	}
	if len(paths) != 1 || paths["/api/v1/runtime/policy-bundles/current"] != 1 {
		t.Fatalf("unexpected endpoints requested: %#v", paths)
	}
}

func TestSyncPolicyBundleValidatesVersionOnNotModifiedResponse(t *testing.T) {
	now := time.Now().UTC()
	raw := unsignedExampleBundle(t, now)
	etag := fmt.Sprintf(`"sha256:%x"`, sha256.Sum256(raw))
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("ETag", etag)
		w.Header().Set("Kei-Policy-Bundle-Version", "42")
		if calls > 1 {
			if r.Header.Get("If-None-Match") != etag {
				t.Errorf("If-None-Match=%q want %q", r.Header.Get("If-None-Match"), etag)
			}
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", policybundle.ContentType)
		_, _ = w.Write(raw)
	}))
	defer server.Close()
	dir := t.TempDir()
	cfg := Config{RuntimeToken: "kh_live_runtime_test_token_1234567890", RuntimeControlPlaneURL: server.URL, RuntimeStateDir: dir}
	identity := &RuntimeIdentity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001")}
	if err := syncPolicyBundle(context.Background(), cfg, identity, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := syncPolicyBundle(context.Background(), cfg, identity, time.Second); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("bundle calls=%d want 2", calls)
	}
}

func TestSyncPolicyBundleFailsClosedOnIntegrityHeaderMismatch(t *testing.T) {
	for _, tc := range []struct{ name, contentType, etag, version string }{{"etag", "application/vnd.kei.policy-bundle.v1+json", `"sha256:wrong"`, "42"}, {"version", "application/vnd.kei.policy-bundle.v1+json", "", "43"}, {"media type", "application/json", "", "42"}} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC()
			raw := unsignedExampleBundle(t, now)
			digest := fmt.Sprintf(`"sha256:%x"`, sha256.Sum256(raw))
			etag := tc.etag
			if etag == "" {
				etag = digest
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				w.Header().Set("ETag", etag)
				w.Header().Set("Kei-Policy-Bundle-Version", tc.version)
				_, _ = w.Write(raw)
			}))
			defer server.Close()
			dir := t.TempDir()
			cfg := Config{RuntimeToken: "kh_live_runtime_test_token_1234567890", RuntimeControlPlaneURL: server.URL, RuntimeStateDir: dir}
			identity := &RuntimeIdentity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001")}
			if err := syncPolicyBundle(context.Background(), cfg, identity, time.Second); err == nil {
				t.Fatal("invalid response headers accepted")
			}
			store, err := policybundle.OpenStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			if _, state, err := store.Check(identity.ID, identity.OrgID, *identity.WorkspaceID, now); err == nil || state != policybundle.Invalid {
				t.Fatalf("rejected response state=%s err=%v", state, err)
			}
		})
	}
}

func TestPolicyBundleEndpointRevocationDeletesPersistedEnforcementState(t *testing.T) {
	now := time.Now().UTC()
	stateDir := t.TempDir()
	_, store := mustActivateTestBundle(t, stateDir, now)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/runtime/policy-bundles/current" {
			http.Error(w, "revoked", http.StatusForbidden)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	cfg := Config{RuntimeToken: "kh_live_runtime_test_token_1234567890", RuntimeControlPlaneURL: server.URL, RuntimeStateDir: stateDir}
	identity := &RuntimeIdentity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001")}
	if err := syncPolicyBundle(context.Background(), cfg, identity, time.Second); err == nil {
		t.Fatal("expected revoked control-plane request to fail")
	}
	if _, state, err := store.Check(identity.ID, identity.OrgID, *identity.WorkspaceID, time.Now().UTC()); err == nil || state != policybundle.Revoked {
		t.Fatalf("after revocation state=%s err=%v", state, err)
	}
}

func TestPolicyControlPlaneBundleRequestUsesValidatedTLSAndRuntimeToken(t *testing.T) {
	raw := unsignedExampleBundle(t, time.Now().UTC())
	digest := fmt.Sprintf(`"sha256:%x"`, sha256.Sum256(raw))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer kh_live_runtime_test_token_1234567890" {
			t.Error("runtime token missing on HTTPS request")
		}
		w.Header().Set("Content-Type", policybundle.ContentType)
		w.Header().Set("ETag", digest)
		w.Header().Set("Kei-Policy-Bundle-Version", "42")
		_, _ = w.Write(raw)
	}))
	defer server.Close()
	client := newPolicyControlClient(server.URL, "kh_live_runtime_test_token_1234567890", time.Second, true)
	client.http = server.Client()
	client.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	body, etag, contentType, version, unchanged, err := client.FetchBundle(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if unchanged || string(body) != string(raw) || etag != digest || version != 42 || contentType != policybundle.ContentType {
		t.Fatalf("body=%t etag=%q content-type=%q version=%d unchanged=%t", string(body) == string(raw), etag, contentType, version, unchanged)
	}
}

func TestPolicyControlPlaneURLRequiresValidatedHTTPSExceptExplicitLoopbackTests(t *testing.T) {
	for _, tc := range []struct {
		url                        string
		allowLoopbackHTTP, wantErr bool
	}{{"https://catalog.example.com", false, false}, {"https://catalog.example.com:8443", false, false}, {"http://127.0.0.1:8080", false, true}, {"http://127.0.0.1:8080", true, false}, {"http://localhost:8080", true, false}, {"http://catalog.example.com", true, true}, {"https://user:password@catalog.example.com", true, true}, {"https://catalog.example.com/path", true, true}, {"https://catalog.example.com?token=x", true, true}, {"https://catalog.example.com#fragment", true, true}, {"file:///etc/passwd", true, true}} {
		if err := validatePolicyControlPlaneURL(tc.url, tc.allowLoopbackHTTP); (err != nil) != tc.wantErr {
			t.Errorf("validate(%q) err=%v wantErr=%v", tc.url, err, tc.wantErr)
		}
	}
}

func TestPolicyControlClientDoesNotFollowRedirects(t *testing.T) {
	called := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/stolen", http.StatusFound)
	}))
	defer server.Close()
	client := newPolicyControlClient(server.URL, "kh_live_runtime_test_token_1234567890", time.Second, true)
	_, _, _, _, _, err := client.FetchBundle(context.Background(), "")
	if err == nil {
		t.Fatal("redirect response was accepted")
	}
	if called {
		t.Fatal("runtime followed redirect to a different origin")
	}
}
