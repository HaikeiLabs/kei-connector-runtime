package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

type testPolicyConfig struct {
	policyStateDir  string
	token           string
	controlPlaneURL string
	isProduction    bool
}

func (c testPolicyConfig) PolicyStateDir() string     { return c.policyStateDir }
func (c testPolicyConfig) Token() string              { return c.token }
func (c testPolicyConfig) ControlPlaneURL() string    { return c.controlPlaneURL }
func (c testPolicyConfig) IsProduction() bool         { return c.isProduction }
func (c testPolicyConfig) Validate() error            { return nil }
func (c testPolicyConfig) IsRuntime() bool            { return false }
func (c testPolicyConfig) PolicyAuditPath() string    { return "" }
func (c testPolicyConfig) PolicyAuditMaxBytes() int64 { return 0 }

func strPtr(s string) *string { return &s }

func unsignedV2ExampleBundle(t *testing.T, now time.Time) []byte {
	t.Helper()
	bundle, err := json.Marshal(map[string]any{
		"schema": "kei.policy-bundle/v2", "bundle_id": "bundle-v2-client-test", "bundle_version": 43, "policy_revision": 7,
		"issuer":    policybundle.Issuer,
		"audience":  map[string]any{"installation_id": "inst-fixture-0001", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001"},
		"issued_at": now.Format(time.RFC3339Nano), "not_after": now.Add(time.Hour).Format(time.RFC3339Nano),
		"refresh":            map[string]any{"poll_interval_seconds": 60, "stale_after_seconds": 300},
		"subject_resolution": map[string]any{"mode": "bundle", "max_cache_seconds": 30},
		"policy_set": map[string]any{
			"schema": "kei.policy-set/v2", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "match_semantics": "kei.match/v2",
			"evaluation": map[string]any{"precedence": []string{"priority_desc", "deny_before_permit", "policy_id_asc"}, "checks": "per_capability_first_match_and", "default": "deny"},
			"tools":      []any{}, "checks": []any{}, "tool_policies": []any{}, "harness_match_semantics": "kei.harness-match/v1", "harness_policies": []any{},
		},
		"agent_connector_bindings": []any{},
		"identities":               []any{map[string]any{"source": "discord", "external_id": "ext-v2-client-test", "user_id": "u-v2-client-test", "status": "linked", "groups": []string{"members"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func TestSyncPolicyBundleRequestsV1ByDefault(t *testing.T) {
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
			if r.Header.Get("Accept") != policyBundleAcceptV1 {
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
	cfg := testPolicyConfig{token: "kh_live_runtime_test_token_1234567890", controlPlaneURL: server.URL, policyStateDir: stateDir}
	identity := &Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001")}
	if err := SyncPolicyBundle(context.Background(), cfg, identity, time.Second); err != nil {
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

func TestSyncPolicyBundleAcceptsV2AndValidatesItsNotModifiedETagAndVersion(t *testing.T) {
	now := time.Now().UTC()
	raw := unsignedV2ExampleBundle(t, now)
	etag := fmt.Sprintf(`"sha256:%x"`, sha256.Sum256(raw))
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got := r.Header.Get("Accept"); got != policyBundleAcceptV2 {
			t.Errorf("Accept=%q want %q", got, policyBundleAcceptV2)
		}
		if calls > 1 {
			if got := r.Header.Get("If-None-Match"); got != etag {
				t.Errorf("If-None-Match=%q want %q", got, etag)
			}
			w.Header().Set("ETag", etag)
			w.Header().Set("Kei-Policy-Bundle-Version", "43")
			w.Header().Set("Content-Type", policybundle.ContentTypeV2)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", policybundle.ContentTypeV2)
		w.Header().Set("ETag", etag)
		w.Header().Set("Kei-Policy-Bundle-Version", "43")
		_, _ = w.Write(raw)
	}))
	defer server.Close()
	dir := t.TempDir()
	cfg := testPolicyConfig{token: "kh_live_runtime_test_token_1234567890", controlPlaneURL: server.URL, policyStateDir: dir}
	identity := &Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001")}
	if err := SyncPolicyBundleV2Ready(context.Background(), cfg, identity, time.Second); err != nil {
		t.Fatalf("sync v2 bundle: %v", err)
	}
	store, err := policybundle.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	active, state, err := store.Check(identity.ID, identity.OrgID, *identity.WorkspaceID, time.Now().UTC())
	if err != nil || state != policybundle.Active || active == nil || active.Payload.Schema != "kei.policy-bundle/v2" || active.Payload.BundleVersion != 43 {
		t.Fatalf("v2 bundle=%v state=%s err=%v", active, state, err)
	}
	if err := SyncPolicyBundleV2Ready(context.Background(), cfg, identity, time.Second); err != nil {
		t.Fatalf("sync unchanged v2 bundle: %v", err)
	}
	if calls != 2 {
		t.Fatalf("bundle calls=%d want 2", calls)
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
		if r.Header.Get("Accept") != policyBundleAcceptV1 {
			t.Errorf("Accept=%q want %q", r.Header.Get("Accept"), policyBundleAcceptV1)
		}
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
	cfg := testPolicyConfig{token: "kh_live_runtime_test_token_1234567890", controlPlaneURL: server.URL, policyStateDir: dir}
	identity := &Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001")}
	if err := SyncPolicyBundle(context.Background(), cfg, identity, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := SyncPolicyBundle(context.Background(), cfg, identity, time.Second); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("bundle calls=%d want 2", calls)
	}
}

func TestSyncPolicyBundleFailsClosedOnIntegrityHeaderMismatch(t *testing.T) {
	for _, tc := range []struct{ name, contentType, etag, version string }{{"etag", "application/vnd.kei.policy-bundle.v1+json", `"sha256:wrong"`, "42"}, {"version", "application/vnd.kei.policy-bundle.v1+json", "", "43"}, {"media type", "application/json", "", "42"}, {"schema-media mismatch", policybundle.ContentTypeV2, "", "42"}} {
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
			cfg := testPolicyConfig{token: "kh_live_runtime_test_token_1234567890", controlPlaneURL: server.URL, policyStateDir: dir}
			identity := &Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001")}
			if err := SyncPolicyBundle(context.Background(), cfg, identity, time.Second); err == nil {
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

func TestPolicyBundleEndpointAuthorizationDenialDoesNotRevokeState(t *testing.T) {
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
	cfg := testPolicyConfig{token: "kh_live_runtime_test_token_1234567890", controlPlaneURL: server.URL, policyStateDir: stateDir}
	identity := &Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001")}
	if err := SyncPolicyBundle(context.Background(), cfg, identity, time.Second); err == nil {
		t.Fatal("expected revoked control-plane request to fail")
	}
	if _, state, err := store.Check(identity.ID, identity.OrgID, *identity.WorkspaceID, time.Now().UTC()); err != nil || state != policybundle.Active {
		t.Fatalf("after authorization denial state=%s err=%v", state, err)
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
	client := NewPolicyControlClient(server.URL, "kh_live_runtime_test_token_1234567890", time.Second, true)
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
		if err := ValidatePolicyControlPlaneURL(tc.url, tc.allowLoopbackHTTP); (err != nil) != tc.wantErr {
			t.Errorf("validate(%q) err=%v wantErr=%v", tc.url, err, tc.wantErr)
		}
	}
}

func TestBundleRefreshError(t *testing.T) {
	tests := []struct {
		name   string
		err    *bundleRefreshError
		want   string
		unwrap error
	}{
		{
			name:   "409 no body",
			err:    &bundleRefreshError{HTTPStatus: 409, wrapped: ErrPolicyBundleNotReady},
			want:   "HTTP 409",
			unwrap: ErrPolicyBundleNotReady,
		},
		{
			name:   "409 with reason detail",
			err:    &bundleRefreshError{HTTPStatus: 409, Reason: "not_ready", Detail: "policy not published", wrapped: ErrPolicyBundleNotReady},
			want:   "not_ready",
			unwrap: ErrPolicyBundleNotReady,
		},
		{
			name:   "403 with reason",
			err:    &bundleRefreshError{HTTPStatus: 403, Reason: "unauthorized", wrapped: ErrPolicyAuthorizationDenied},
			want:   "unauthorized",
			unwrap: ErrPolicyAuthorizationDenied,
		},
		{
			name:   "503 no body",
			err:    &bundleRefreshError{HTTPStatus: 503},
			want:   "HTTP 503",
			unwrap: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.err.Error()
			if !strings.Contains(got, tc.want) {
				t.Errorf("Error()=%q does not contain %q", got, tc.want)
			}
			if tc.unwrap != nil {
				if !errors.Is(tc.err, tc.unwrap) {
					t.Errorf("errors.Is(%v, %v) = false", tc.err, tc.unwrap)
				}
			}
		})
	}
}

func TestBundleRefreshErrorLogFields(t *testing.T) {
	err := &bundleRefreshError{HTTPStatus: 409, Reason: "not_ready", Detail: "something"}
	fields := err.logFields()
	if len(fields) < 4 {
		t.Fatalf("logFields()=%v expected at least 4 elements", fields)
	}
}

func TestParseBundleErrorResponse(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		wantReason string
		wantDetail string
		wantUnwrap error
		wantHTTP   int
	}{
		{
			name:       "409 JSON body",
			status:     409,
			body:       `{"reason":"not_ready","detail":"policy not published yet"}`,
			wantReason: "not_ready",
			wantDetail: "policy not published yet",
			wantUnwrap: ErrPolicyBundleNotReady,
			wantHTTP:   409,
		},
		{
			name:       "409 raw body",
			status:     409,
			body:       "not ready",
			wantDetail: "not ready",
			wantUnwrap: ErrPolicyBundleNotReady,
			wantHTTP:   409,
		},
		{
			name:       "403 JSON body",
			status:     403,
			body:       `{"reason":"unauthorized"}`,
			wantReason: "unauthorized",
			wantUnwrap: ErrPolicyAuthorizationDenied,
			wantHTTP:   403,
		},
		{
			name:       "503 JSON body",
			status:     503,
			body:       `{"reason":"overloaded","detail":"too many requests"}`,
			wantReason: "overloaded",
			wantDetail: "too many requests",
			wantUnwrap: nil,
			wantHTTP:   503,
		},
		{
			name:       "503 empty body",
			status:     503,
			body:       "",
			wantUnwrap: nil,
			wantHTTP:   503,
		},
		{
			name:       "HTML error page newlines stripped and truncated",
			status:     502,
			body:       "<html>\n<head><title>502 Bad Gateway</title></head>\n<body>\n<center><h1>502 Bad Gateway</h1></center>\n</body>\n</html>",
			wantDetail: "<html> <head><title>502 Bad Gateway</title></head> <body> <center><h1>502 Bad Gateway</h1></center> </body> </html>",
			wantUnwrap: nil,
			wantHTTP:   502,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tc.status,
				Body:       io.NopCloser(strings.NewReader(tc.body)),
			}
			bre := parseBundleErrorResponse(resp, false)
			if bre == nil {
				t.Fatal("parseBundleErrorResponse returned nil")
			}
			if bre.HTTPStatus != tc.wantHTTP {
				t.Errorf("HTTPStatus=%d want %d", bre.HTTPStatus, tc.wantHTTP)
			}
			if bre.Reason != tc.wantReason {
				t.Errorf("Reason=%q want %q", bre.Reason, tc.wantReason)
			}
			if !strings.Contains(bre.Detail, tc.wantDetail) {
				t.Errorf("Detail=%q does not contain %q", bre.Detail, tc.wantDetail)
			}
			if tc.wantUnwrap != nil && !errors.Is(bre, tc.wantUnwrap) {
				t.Errorf("errors.Is(%v, %v) = false", bre, tc.wantUnwrap)
			}
		})
	}
}

func TestParseBundleErrorResponseTruncatesLargeBody(t *testing.T) {
	big := strings.Repeat("x", 8192)
	resp := &http.Response{
		StatusCode: 409,
		Body:       io.NopCloser(strings.NewReader(big)),
	}
	bre := parseBundleErrorResponse(resp, false)
	if bre == nil {
		t.Fatal("parseBundleErrorResponse returned nil")
	}
	wantMax := detailMaxRunes + 3 // 3 for "..."
	if len(bre.Detail) > wantMax {
		t.Errorf("Detail len=%d; want <=%d", len(bre.Detail), wantMax)
	}
	if !strings.HasSuffix(bre.Detail, "...") {
		t.Errorf("Detail=%q does not end with '...'", bre.Detail)
	}
	if strings.ContainsAny(bre.Detail, "\n\r") {
		t.Errorf("Detail=%q contains newline or carriage return", bre.Detail)
	}
}

func TestLogSyncFailureRateLimiting(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(prev)

	r := &PolicyRefresher{}
	berr := &bundleRefreshError{HTTPStatus: 409, Reason: "not_ready", wrapped: ErrPolicyBundleNotReady}

	// First call should always log.
	r.logSyncFailure(berr, "cold", "cold")
	if buf.Len() == 0 {
		t.Fatal("first failure did not log")
	}
	firstLines := strings.Count(buf.String(), "\n")

	// Calls 2-9 with same state should NOT log (rate-limited).
	for i := 2; i < 10; i++ {
		r.logSyncFailure(berr, "cold", "cold")
	}
	lines := strings.Count(buf.String(), "\n")
	if lines != firstLines {
		t.Fatalf("logs increased from %d to %d during rate-limiting window", firstLines, lines)
	}

	// Call 10 should log (tick % 10 == 0).
	r.logSyncFailure(berr, "cold", "cold")
	lines2 := strings.Count(buf.String(), "\n")
	if lines2 <= lines {
		t.Fatal("expected log on 10th tick, got none")
	}

	// State change should log immediately regardless of tick.
	r.logSyncFailure(berr, "cold", "stale_but_valid")
	lines3 := strings.Count(buf.String(), "\n")
	if lines3 <= lines2 {
		t.Fatal("expected log on state transition, got none")
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
	client := NewPolicyControlClient(server.URL, "kh_live_runtime_test_token_1234567890", time.Second, true)
	_, _, _, _, _, err := client.FetchBundle(context.Background(), "")
	if err == nil {
		t.Fatal("redirect response was accepted")
	}
	if called {
		t.Fatal("runtime followed redirect to a different origin")
	}
}
