package runtime_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	connectorruntime "github.com/HaikeiLabs/kei-connector-runtime"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

const policyTestToken = "kh_live_runtime_test_token_1234567890"

func strPtr(s string) *string { return &s }

var policyTestIdentity = connectorruntime.RuntimeIdentity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001"), Platform: "cli", Status: "active", BindingStatus: "verified"}

// fakePolicyCatalog serves whoami and the current policy bundle: status (when
// set) replaces the bundle response, and badETag sends a digest mismatch.
type fakePolicyCatalog struct {
	mu          sync.Mutex
	body        []byte
	status      int
	badETag     bool
	whoamiCode  int
	bundleCalls int
}

func (f *fakePolicyCatalog) set(body []byte, status int, badETag bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.body, f.status, f.badETag = body, status, badETag
}

func (f *fakePolicyCatalog) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+policyTestToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/api/v1/runtime/whoami":
		if f.whoamiCode != 0 {
			w.WriteHeader(f.whoamiCode)
			return
		}
		_ = json.NewEncoder(w).Encode(policyTestIdentity)
	case "/api/v1/runtime/policy-bundles/current":
		f.bundleCalls++
		if f.status != 0 && f.status != http.StatusOK {
			w.WriteHeader(f.status)
			return
		}
		var doc struct {
			Version int64 `json:"bundle_version"`
		}
		_ = json.Unmarshal(f.body, &doc)
		etag := fmt.Sprintf(`"sha256:%x"`, sha256.Sum256(f.body))
		if f.badETag {
			etag = `"sha256:0000"`
		}
		if r.Header.Get("If-None-Match") == etag {
			w.Header().Set("ETag", etag)
			w.Header().Set("Kei-Policy-Bundle-Version", strconv.FormatInt(doc.Version, 10))
			w.WriteHeader(http.StatusNotModified)
			return
		}
		contentType := policybundle.ContentType
		if bytes.Contains(f.body, []byte("kei.policy-bundle/v2")) {
			contentType = policybundle.ContentTypeV2
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("ETag", etag)
		w.Header().Set("Kei-Policy-Bundle-Version", strconv.FormatInt(doc.Version, 10))
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(f.body)
	default:
		http.NotFound(w, r)
	}
}

// unsignedExampleBundle is the vendored v2 example payload re-dated to now,
// addressed to the fixture installation at bundle version 42 and policy
// revision 17. It installs the real v2 schema validator.
func unsignedExampleBundle(t *testing.T, now time.Time) []byte {
	t.Helper()
	policybundle.SetV2SchemaValidator(runtimeV2SchemaValidator(t))
	b, err := os.ReadFile(filepath.Join("..", "docs", "contracts", "examples", "policy-bundle-v2.payload.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	doc["bundle_version"] = 42
	doc["policy_revision"] = 17
	doc["audience"] = map[string]any{"installation_id": "inst-fixture-0001", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001"}
	doc["issued_at"] = now.UTC().Format(time.RFC3339)
	doc["not_after"] = now.UTC().Add(12 * time.Hour).Format(time.RFC3339)
	set := doc["policy_set"].(map[string]any)
	set["org_id"], set["workspace_id"] = "org-fixture-0001", "ws-fixture-0001"
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func bundleWithVersion(t *testing.T, now time.Time, version int64) []byte {
	t.Helper()
	return bytes.Replace(unsignedExampleBundle(t, now), []byte(`"bundle_version": 42`), []byte(fmt.Sprintf(`"bundle_version": %d`, version)), 1)
}

func policyTestConfig(url, dir string) connectorruntime.Config {
	return connectorruntime.Config{RuntimeToken: policyTestToken, RuntimeControlPlaneURL: url, RuntimeStateDir: dir}
}

func decodeStatus(t *testing.T, b []byte) policybundle.Status {
	t.Helper()
	var st policybundle.Status
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatalf("decode policy status %q: %v", b, err)
	}
	return st
}

func TestPolicySyncPersistsSchemaExampleAndShowReadsItOffline(t *testing.T) {
	catalog := &fakePolicyCatalog{body: unsignedExampleBundle(t, time.Now().UTC())}
	server := httptest.NewServer(catalog)
	dir := t.TempDir()
	cfg := policyTestConfig(server.URL, dir)

	var stdout, stderr bytes.Buffer
	identityFunc := func() (*keiruntime.Identity, error) {
		id, err := connectorruntime.NewRuntimeClient(server.URL, 10*time.Second).WhoAmI(context.Background(), policyTestToken)
		if err != nil {
			return nil, err
		}
		return &keiruntime.Identity{ID: id.ID, OrgID: id.OrgID, WorkspaceID: id.WorkspaceID}, nil
	}
	syncBundle := func(identity *keiruntime.Identity) error {
		return connectorruntime.SyncPolicyBundle(context.Background(), cfg, &connectorruntime.RuntimeIdentity{
			ID: identity.ID, OrgID: identity.OrgID, WorkspaceID: identity.WorkspaceID,
		}, 10*time.Second)
	}
	if code := keiruntime.RunPolicySync(context.Background(), nil, &stdout, &stderr, cfg, identityFunc, syncBundle, connectorruntime.IsRuntimeRevocation, func() { connectorruntime.RevokePolicyState(cfg) }); code != 0 {
		t.Fatalf("policy sync exit=%d stderr=%s", code, stderr.String())
	}
	st := decodeStatus(t, stdout.Bytes())
	if st.State != policybundle.Active || st.BundleVersion != 42 || st.PolicyRevision != 17 {
		t.Fatalf("sync status = %+v", st)
	}
	if st.BundleDigest != fmt.Sprintf("sha256:%x", sha256.Sum256(catalog.body)) {
		t.Fatalf("digest = %s", st.BundleDigest)
	}
	for _, name := range []string{"bundle.json", "state.json"} {
		info, err := os.Stat(filepath.Join(dir, "policy", name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %04o, want 0600", name, info.Mode().Perm())
		}
	}
	if info, _ := os.Stat(filepath.Join(dir, "policy")); info.Mode().Perm() != 0o700 {
		t.Fatalf("policy dir mode = %04o, want 0700", info.Mode().Perm())
	}
	persisted, _ := os.ReadFile(filepath.Join(dir, "policy", "bundle.json"))
	if !bytes.Equal(persisted, catalog.body) {
		t.Fatal("persisted bundle bytes differ from the fetched payload")
	}

	server.Close() // show never calls the network
	stdout.Reset()
	if code := keiruntime.RunPolicyShow(nil, &stdout, &stderr, cfg); code != 0 {
		t.Fatalf("policy show exit=%d stderr=%s", code, stderr.String())
	}
	if shown := decodeStatus(t, stdout.Bytes()); shown.BundleVersion != 42 || shown.State != policybundle.Active || shown.Audience == nil || shown.Audience.InstallationID != "inst-fixture-0001" {
		t.Fatalf("show status = %+v", shown)
	}
	if bytes.Contains(stdout.Bytes(), []byte("src_pattern")) {
		t.Fatal("policy show printed bundle contents")
	}
}

func TestPolicySyncRejectsInvalidSchemaExampleAndStaysDenyOnly(t *testing.T) {
	invalid := bytes.Replace(unsignedExampleBundle(t, time.Now().UTC()), []byte(`"issuer": "kei-policy-catalog"`), []byte(`"issuer": "kei-policy-catalog", "signatures": []`), 1)
	server := httptest.NewServer(&fakePolicyCatalog{body: invalid})
	defer server.Close()
	dir := t.TempDir()
	cfg := policyTestConfig(server.URL, dir)
	var stdout, stderr bytes.Buffer
	idFunc := func() (*keiruntime.Identity, error) {
		id, err := connectorruntime.NewRuntimeClient(server.URL, 10*time.Second).WhoAmI(context.Background(), policyTestToken)
		if err != nil {
			return nil, err
		}
		return &keiruntime.Identity{ID: id.ID, OrgID: id.OrgID, WorkspaceID: id.WorkspaceID}, nil
	}
	syncFn := func(identity *keiruntime.Identity) error {
		return connectorruntime.SyncPolicyBundle(context.Background(), cfg, &connectorruntime.RuntimeIdentity{
			ID: identity.ID, OrgID: identity.OrgID, WorkspaceID: identity.WorkspaceID,
		}, 10*time.Second)
	}
	if code := keiruntime.RunPolicySync(context.Background(), nil, &stdout, &stderr, cfg, idFunc, syncFn, connectorruntime.IsRuntimeRevocation, func() { connectorruntime.RevokePolicyState(cfg) }); code == 0 {
		t.Fatal("policy sync accepted a bundle with an unknown field")
	}
	if st := decodeStatus(t, stdout.Bytes()); st.State == policybundle.Active || st.BundleVersion != 0 {
		t.Fatalf("status after rejected bundle = %+v", st)
	}
	if _, err := os.Stat(filepath.Join(dir, "policy", "bundle.json")); !os.IsNotExist(err) {
		t.Fatalf("rejected bundle was persisted: %v", err)
	}
}

func TestPolicyBundleForbiddenDoesNotClaimInstallationRevoked(t *testing.T) {
	catalog := &fakePolicyCatalog{body: unsignedExampleBundle(t, time.Now().UTC())}
	server := httptest.NewServer(catalog)
	defer server.Close()
	dir := t.TempDir()
	cfg := policyTestConfig(server.URL, dir)
	var stdout, stderr bytes.Buffer
	idFunc := func() (*keiruntime.Identity, error) {
		id, err := connectorruntime.NewRuntimeClient(server.URL, 10*time.Second).WhoAmI(context.Background(), policyTestToken)
		if err != nil {
			return nil, err
		}
		return &keiruntime.Identity{ID: id.ID, OrgID: id.OrgID, WorkspaceID: id.WorkspaceID}, nil
	}
	syncFn := func(identity *keiruntime.Identity) error {
		return connectorruntime.SyncPolicyBundle(context.Background(), cfg, &connectorruntime.RuntimeIdentity{
			ID: identity.ID, OrgID: identity.OrgID, WorkspaceID: identity.WorkspaceID,
		}, 10*time.Second)
	}
	if code := keiruntime.RunPolicySync(context.Background(), nil, &stdout, &stderr, cfg, idFunc, syncFn, connectorruntime.IsRuntimeRevocation, func() { connectorruntime.RevokePolicyState(cfg) }); code != 0 {
		t.Fatalf("first sync exit=%d %s", code, stderr.String())
	}
	catalog.mu.Lock()
	catalog.status = http.StatusForbidden
	catalog.mu.Unlock()
	stdout.Reset()
	if code := keiruntime.RunPolicySync(context.Background(), nil, &stdout, &stderr, cfg, idFunc, syncFn, connectorruntime.IsRuntimeRevocation, func() { connectorruntime.RevokePolicyState(cfg) }); code == 0 {
		t.Fatal("sync succeeded for a revoked installation")
	}
	stdout.Reset()
	_ = keiruntime.RunPolicyShow(nil, &stdout, &stderr, cfg)
	if st := decodeStatus(t, stdout.Bytes()); st.State != policybundle.Active {
		t.Fatalf("state = %s, want active with refresh failure recorded", st.State)
	}
	if _, err := os.Stat(filepath.Join(dir, "policy", "bundle.json")); err != nil {
		t.Fatalf("authorization failure removed valid persisted bundle: %v", err)
	}
}

// TestPolicyBundleStateMachine drives ADR-026 §6 end to end through the
// sync path and the local evaluator: cold start, activation, a rejected
// candidate that never replaces the active bundle, rollback, a newer
// bundle, expiry and revocation.
func TestPolicyBundleStateMachine(t *testing.T) {
	now := time.Now().UTC()
	catalog := &fakePolicyCatalog{status: http.StatusConflict}
	server := httptest.NewServer(catalog)
	defer server.Close()
	dir := t.TempDir()
	cfg := policyTestConfig(server.URL, dir)
	identity := policyTestIdentity
	sessions := pdp.NewSessions()
	sessionID, err := sessions.Create(pdp.Subject{UserID: "u-fixture", Status: pdp.StatusLinked})
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := pdp.New(dir, pdp.Audience{InstallationID: identity.ID, OrgID: identity.OrgID, WorkspaceID: *identity.WorkspaceID}, sessions)
	if err != nil {
		t.Fatal(err)
	}
	connectorGet := pdp.Request{Session: sessionID, Connector: &pdp.ConnectorTarget{ConnectorID: "conn-github-0001", Capability: "issue.get"}}
	expect := func(step string, allow bool, reasonCode pdp.ReasonCode, version int64) {
		t.Helper()
		d, err := evaluator.Evaluate(context.Background(), connectorGet)
		if err != nil {
			t.Fatal(err)
		}
		if d.Allow != allow || d.ReasonCode != reasonCode || d.BundleVersion != version {
			t.Fatalf("%s: decision = %+v, want allow=%v reason_code=%q version=%d", step, d, allow, reasonCode, version)
		}
	}
	sync := func() error {
		return connectorruntime.SyncPolicyBundle(context.Background(), cfg, &identity, time.Second)
	}

	if err := sync(); err != nil {
		t.Fatalf("409 not ready must leave the runtime cold without failing: %v", err)
	}
	expect("cold start", false, "policy_bundle_missing", 0)

	catalog.set(bundleWithVersion(t, now, 42), http.StatusOK, false)
	if err := sync(); err != nil {
		t.Fatal(err)
	}
	expect("activated v42", false, "preflight_required", 42)

	catalog.set(bundleWithVersion(t, now, 43), http.StatusOK, true)
	if err := sync(); err == nil {
		t.Fatal("candidate with a digest mismatch was accepted")
	}
	expect("invalid candidate keeps v42", false, "preflight_required", 42)

	catalog.set(bytes.Replace(bundleWithVersion(t, now, 44), []byte(`"inst-fixture-0001"`), []byte(`"inst-other-0001"`), 1), http.StatusOK, false)
	if err := sync(); err == nil {
		t.Fatal("candidate for another installation was accepted")
	}
	expect("wrong audience keeps v42", false, "preflight_required", 42)

	catalog.set(bundleWithVersion(t, now, 41), http.StatusOK, false)
	if err := sync(); err == nil {
		t.Fatal("rollback to v41 was accepted")
	}
	expect("rollback keeps v42", false, "preflight_required", 42)

	catalog.set(bundleWithVersion(t, now, 43), http.StatusOK, false)
	if err := sync(); err != nil {
		t.Fatal(err)
	}
	expect("refresh to v43", false, "preflight_required", 43)

	catalog.set(nil, http.StatusServiceUnavailable, false)
	if err := sync(); err == nil {
		t.Fatal("503 reported success")
	}
	expect("unreachable catalog keeps v43", false, "preflight_required", 43)

	store, err := policybundle.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := store.Status(now.Add(11 * time.Minute)); st.State != policybundle.Stale {
		t.Fatalf("state after failing refreshes past stale_after = %s, want stale_but_valid", st.State)
	}
	if _, state, _ := store.Check(identity.ID, identity.OrgID, *identity.WorkspaceID, now.Add(12*time.Hour)); state != policybundle.Expired {
		t.Fatalf("state past not_after = %s, want expired", state)
	}
	expect("expired", false, "policy_bundle_expired", 0)

	catalog.set(nil, http.StatusUnauthorized, false)
	_ = sync()
	expect("bundle endpoint authorization denied", false, "policy_bundle_expired", 0)
}

func TestPolicyRefresherPollsAtBundleIntervalAndHoldsTheLock(t *testing.T) {
	catalog := &fakePolicyCatalog{body: unsignedExampleBundle(t, time.Now().UTC())}
	server := httptest.NewServer(catalog)
	defer server.Close()
	dir := t.TempDir()
	cfg := policyTestConfig(server.URL, dir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ticks := make(chan time.Time)
	waits := make(chan time.Duration, 8)
	results := make(chan error, 8)
	var identities int
	r := keiruntime.NewPolicyRefresher(cfg,
		func() (*keiruntime.Identity, error) {
			id, err := connectorruntime.NewRuntimeClient(server.URL, 10*time.Second).WhoAmI(context.Background(), policyTestToken)
			if err != nil {
				return nil, err
			}
			return &keiruntime.Identity{ID: id.ID, OrgID: id.OrgID, WorkspaceID: id.WorkspaceID}, nil
		},
		func(identity *keiruntime.Identity) error {
			return connectorruntime.SyncPolicyBundle(context.Background(), cfg, &connectorruntime.RuntimeIdentity{
				ID: identity.ID, OrgID: identity.OrgID, WorkspaceID: identity.WorkspaceID,
			}, 10*time.Second)
		},
		connectorruntime.IsRuntimeRevocation,
		func() { connectorruntime.RevokePolicyState(cfg) },
	)
	r.Jitter = func(d time.Duration) time.Duration { return d }
	r.After = func(d time.Duration) <-chan time.Time { waits <- d; return ticks }
	r.OnIdentity = func(*keiruntime.Identity) { identities++ }
	r.AfterSync = func(err error) { results <- err }
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	if err := <-results; err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if d := <-waits; d != 60*time.Second {
		t.Fatalf("poll interval = %s, want the bundle's 60s", d)
	}

	// A second refresher on the same state directory does not run.
	second := keiruntime.NewPolicyRefresher(cfg,
		func() (*keiruntime.Identity, error) { return nil, errors.New("should not be called") },
		func(*keiruntime.Identity) error { t.Error("second refresher synced"); return nil },
		nil,
		func() {},
	)
	second.Run(ctx)

	ticks <- time.Now()
	if err := <-results; err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	<-waits
	cancel()
	<-done
	catalog.mu.Lock()
	calls := catalog.bundleCalls
	catalog.mu.Unlock()
	if calls != 2 || identities != 2 {
		t.Fatalf("bundle calls = %d, identities = %d; want 2 and 2", calls, identities)
	}
}

func TestPolicyPollIntervalClampAndJitter(t *testing.T) {
	for in, want := range map[time.Duration]time.Duration{10 * time.Second: 30 * time.Second, 60 * time.Second: 60 * time.Second, time.Hour: 300 * time.Second} {
		if got := keiruntime.ClampPollInterval(in); got != want {
			t.Fatalf("clamp(%s) = %s, want %s", in, got, want)
		}
	}
	for range 200 {
		if d := keiruntime.PolicyJitter(60 * time.Second); d < 54*time.Second || d > 66*time.Second {
			t.Fatalf("jitter = %s outside ±10%%", d)
		}
	}
}
