package runtime_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	connectorruntime "github.com/HaikeiLabs/kei-connector-runtime"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/credrelease"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

// perSubjectI11 is a fake identity service that releases a github credential
// named after the subject token ("gh-" + token), so a credential shows whose
// session it came from. A fetch for slowToken waits until release is closed.
type perSubjectI11 struct {
	slowToken string
	release   chan struct{}
}

func (f *perSubjectI11) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Kei-Subject-Token")
	if f.slowToken != "" && token == f.slowToken {
		<-f.release
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"credentials": []map[string]string{{"provider": "github", "access_token": "gh-" + token, "token_type": "Bearer"}},
	})
}

// multiSessionPDP is a daemon PDP with a bundle linking discord ext-alice
// (group members, which may use web_search) and ext-bob (no group), and
// per-session credential release from f.
func multiSessionPDP(t *testing.T, f *perSubjectI11, emit keiruntime.EmitAuditFunc) (*keiruntime.LocalPDP, http.Handler) {
	t.Helper()
	ids := []policybundle.Identity{
		{Source: "discord", ExternalID: "ext-alice", UserID: "u-alice", Status: "linked", Groups: []string{"members"}, SubjectToken: "st-alice"},
		{Source: "discord", ExternalID: "ext-bob", UserID: "u-bob", Status: "linked", SubjectToken: "st-bob"},
		{Source: "discord", ExternalID: "ext-slow", UserID: "u-slow", Status: "linked", Groups: []string{"members"}, SubjectToken: "st-slow"},
	}
	policy := `[{"id":"p-allow-web-search","name":"allow-web-search","src_pattern":"group:members","dst_pattern":"tool:web_search","action":"permit","priority":50,"enabled":true,"approval_required":false,"scope":{"org_id":"org-fixture-0001","workspace_id":"ws-fixture-0001","agent_id":null}}]`
	dir := t.TempDir()
	activateBundle(t, dir, bundleWithPolicy(t, ids, policy))
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken: policyTestToken, RuntimeControlPlaneURL: "https://kei.example", RuntimeStateDir: dir,
	}, emit)
	l.SetIdentity(&keiruntime.Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001"), AgentID: "agent-fixture-0001"})
	l.SetCredentialStore(credrelease.NewStore(credrelease.NewClient(srv.URL, policyTestToken, 5*time.Second)))
	t.Cleanup(l.Close)
	return l, sessionHandler(t, l)
}

// createSession starts a named session for a discord user and returns its id.
func createSession(t *testing.T, h http.Handler, externalID string) string {
	t.Helper()
	rec := putSession(t, h, `{"schema":"kei.session/v2","source":"discord","external_id":"`+externalID+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("PUT v2 = %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Schema, SessionID, UserID, Status string
		IdleTTLSeconds                    int64 `json:"idle_ttl_seconds"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &struct {
		Schema         *string `json:"schema"`
		SessionID      *string `json:"session_id"`
		UserID         *string `json:"user_id"`
		Status         *string `json:"status"`
		IdleTTLSeconds *int64  `json:"idle_ttl_seconds"`
	}{&out.Schema, &out.SessionID, &out.UserID, &out.Status, &out.IdleTTLSeconds}); err != nil {
		t.Fatal(err)
	}
	if out.Schema != "kei.session/v2" || !strings.HasPrefix(out.SessionID, "ks_") || out.Status != "linked" || out.IdleTTLSeconds <= 0 {
		t.Fatalf("PUT v2 response = %+v", out)
	}
	return out.SessionID
}

// sessionRequest serves one socket request in session id ("" = default).
func sessionRequest(h http.Handler, method, path, id, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if id != "" {
		req.Header.Set("X-Kei-Session", id)
	}
	h.ServeHTTP(rec, req)
	return rec
}

// authorizeIn returns the decision and reason code for web_search in session id.
func authorizeIn(t *testing.T, h http.Handler, id string) (string, string) {
	t.Helper()
	rec := sessionRequest(h, http.MethodPost, "/v1/authorize", id, `{"schema":"kei.authorize-request/v1","tool":"web_search"}`)
	if rec.Code != http.StatusOK {
		t.Errorf("authorize = %d %s", rec.Code, rec.Body.String())
		return "", ""
	}
	var out struct {
		Decision   string `json:"decision"`
		ReasonCode string `json:"reason_code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out.Decision, out.ReasonCode
}

// credentialIn returns the github credential session id holds for subject.
func credentialIn(l *keiruntime.LocalPDP, id, subject string) (string, error) {
	var got string
	err := l.UseCredential(context.Background(), id, subject, "github", func(token string) error {
		got = token
		return nil
	})
	return got, err
}

// TestMultiSessionAuthorizeIndependently: two sessions with different
// subjects, used concurrently, each get the decision for their own subject.
func TestMultiSessionAuthorizeIndependently(t *testing.T) {
	_, h := multiSessionPDP(t, &perSubjectI11{}, nil)
	alice, bob := createSession(t, h, "ext-alice"), createSession(t, h, "ext-bob")

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if d, r := authorizeIn(t, h, alice); d != "permit" {
				t.Errorf("alice: %s %s, want permit", d, r)
			}
		}()
		go func() {
			defer wg.Done()
			if d, _ := authorizeIn(t, h, bob); d != "deny" {
				t.Errorf("bob: %s, want deny", d)
			}
		}()
	}
	wg.Wait()
}

// TestMultiSessionCredentialsIsolated: each session holds its own subject's
// credentials and can't reach another session's.
func TestMultiSessionCredentialsIsolated(t *testing.T) {
	l, h := multiSessionPDP(t, &perSubjectI11{}, nil)
	alice, bob := createSession(t, h, "ext-alice"), createSession(t, h, "ext-bob")

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if tok, err := credentialIn(l, alice, "u-alice"); err != nil || tok != "gh-st-alice" {
				t.Errorf("alice's session released %q, %v", tok, err)
			}
		}()
		go func() {
			defer wg.Done()
			if tok, err := credentialIn(l, bob, "u-bob"); err != nil || tok != "gh-st-bob" {
				t.Errorf("bob's session released %q, %v", tok, err)
			}
		}()
	}
	wg.Wait()

	var denied *credrelease.DeniedError
	// Naming bob as the subject in alice's session reaches nothing.
	if tok, err := credentialIn(l, alice, "u-bob"); !errors.As(err, &denied) || tok != "" {
		t.Errorf("cross-session use released %q, %v", tok, err)
	}
	// Neither the default session nor an unknown id holds anything.
	for _, id := range []string{pdp.DefaultSession, "ks_unknown"} {
		if tok, err := credentialIn(l, id, "u-alice"); !errors.As(err, &denied) || tok != "" {
			t.Errorf("session %q released %q, %v", id, tok, err)
		}
	}
}

// TestMultiSessionUnknownIDFailsClosed: an id that was never created denies
// on every route.
func TestMultiSessionUnknownIDFailsClosed(t *testing.T) {
	_, h := multiSessionPDP(t, &perSubjectI11{}, nil)
	createSession(t, h, "ext-alice")
	if d, r := authorizeIn(t, h, "ks_forged"); d != "deny" || r != "session_not_found" {
		t.Errorf("authorize with an unknown id: %s %s", d, r)
	}
	for _, m := range []string{http.MethodGet, http.MethodDelete} {
		rec := sessionRequest(h, m, "/v1/session", "ks_forged", "")
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "session_not_found") {
			t.Errorf("%s with an unknown id = %d %s", m, rec.Code, rec.Body.String())
		}
	}
}

// TestMultiSessionDeleteIsolation: DELETE ends one named session and flushes
// only its credentials; other named sessions are untouched.
func TestMultiSessionDeleteIsolation(t *testing.T) {
	l, h := multiSessionPDP(t, &perSubjectI11{}, nil)
	alice, bob := createSession(t, h, "ext-alice"), createSession(t, h, "ext-bob")

	if rec := sessionRequest(h, http.MethodDelete, "/v1/session", alice, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE alice = %d", rec.Code)
	}
	if d, r := authorizeIn(t, h, alice); r != "session_not_found" {
		t.Errorf("ended session authorizes: %s %s", d, r)
	}
	if _, err := credentialIn(l, alice, "u-alice"); err == nil {
		t.Error("ended session still releases its credential")
	}
	if tok, err := credentialIn(l, bob, "u-bob"); err != nil || tok != "gh-st-bob" {
		t.Errorf("bob's credential after alice's DELETE: %q %v", tok, err)
	}
	if rec := sessionRequest(h, http.MethodGet, "/v1/session", bob, ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"session_id":"`+bob+`"`) {
		t.Errorf("GET bob = %d %s", rec.Code, rec.Body.String())
	}
}

// TestMultiSessionIdleTTL: an unused session ends after the idle TTL, with
// its credentials.
func TestMultiSessionIdleTTL(t *testing.T) {
	l, h := multiSessionPDP(t, &perSubjectI11{}, nil)
	l.SetSessionIdleTTL(80 * time.Millisecond)

	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	l.SetSessionNow(func() time.Time { return now })

	alice, kept := createSession(t, h, "ext-alice"), createSession(t, h, "ext-bob")
	for range 4 {
		now = now.Add(40 * time.Millisecond)
		authorizeIn(t, h, kept) // use restarts the clock
	}
	if d, r := authorizeIn(t, h, alice); r != "session_not_found" {
		t.Errorf("idle session still authorizes: %s %s", d, r)
	}
	if _, err := credentialIn(l, alice, "u-alice"); err == nil {
		t.Error("idle session still releases its credential")
	}
	if rec := sessionRequest(h, http.MethodGet, "/v1/session", kept, ""); rec.Code != http.StatusOK {
		t.Errorf("a session in use expired: GET = %d", rec.Code)
	}
}

// TestMultiSessionSweeper: the daemon's sweeper ends idle sessions without
// any request touching them.
func TestMultiSessionSweeper(t *testing.T) {
	l, h := multiSessionPDP(t, &perSubjectI11{}, nil)
	l.SetSessionIdleTTL(40 * time.Millisecond)
	createSession(t, h, "ext-alice")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.SweepSessions(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for l.Sessions.Len() > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := l.Sessions.Len(); n != 0 {
		t.Fatalf("%d idle sessions left after the sweep", n)
	}
}

// TestMultiSessionSlowSessionDoesNotBlockAnother: while one session is stuck
// (its credential fetch and a long credential use), another session starts,
// authorizes and uses its credential.
func TestMultiSessionSlowSessionDoesNotBlockAnother(t *testing.T) {
	f := &perSubjectI11{slowToken: "st-slow", release: make(chan struct{})}
	l, h := multiSessionPDP(t, f, nil)
	defer close(f.release)

	// A session whose credential fetch hangs (PUT in flight).
	slowPut := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		slowPut <- putSession(t, h, `{"schema":"kei.session/v2","source":"discord","external_id":"ext-slow"}`)
	}()

	// A session whose credential use runs long (e.g. a long completion).
	alice := createSession(t, h, "ext-alice")
	inUse, finish := make(chan struct{}), make(chan struct{})
	go func() {
		_ = l.UseCredential(context.Background(), alice, "u-alice", "github", func(string) error {
			close(inUse)
			<-finish
			return nil
		})
	}()
	<-inUse
	defer close(finish)

	done := make(chan struct{})
	go func() {
		defer close(done)
		bob := createSession(t, h, "ext-bob")
		if d, _ := authorizeIn(t, h, bob); d != "deny" {
			t.Errorf("bob: %s", d)
		}
		if d, _ := authorizeIn(t, h, alice); d != "permit" {
			t.Errorf("alice, while her credential is in use: %s", d)
		}
		if tok, err := credentialIn(l, bob, "u-bob"); err != nil || tok != "gh-st-bob" {
			t.Errorf("bob's credential: %q %v", tok, err)
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("a slow session blocked another session")
	}
	select {
	case rec := <-slowPut:
		t.Fatalf("the slow PUT finished early: %d", rec.Code)
	default:
	}
}

// TestLegacyDefaultSessionIsNotStored verifies the removed default storage
// cannot be populated; named sessions remain independent and live.
func TestLegacyDefaultSessionIsNotStored(t *testing.T) {
	l, h := multiSessionPDP(t, &perSubjectI11{}, nil)
	if rec := putSession(t, h, `{"schema":"kei.session/v1","source":"discord","external_id":"ext-alice"}`); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_session") {
		t.Fatalf("legacy PUT = %d %s, want invalid_session", rec.Code, rec.Body.String())
	}
	if l.Sessions.Exists(pdp.DefaultSession) {
		t.Fatal("empty session exists after legacy PUT")
	}
	alice, bob := createSession(t, h, "ext-alice"), createSession(t, h, "ext-bob")
	if d, _ := authorizeIn(t, h, alice); d != "permit" {
		t.Errorf("named session (alice): %s, want permit", d)
	}
	if d, _ := authorizeIn(t, h, bob); d != "deny" {
		t.Errorf("named session (bob): %s, want deny", d)
	}
	if _, ok := l.Sessions.Get(pdp.DefaultSession); ok {
		t.Fatal("empty session remains readable")
	}
}

// TestMultiSessionAuditCarriesSessionID: decision events name the session.
func TestMultiSessionAuditCarriesSessionID(t *testing.T) {
	var mu sync.Mutex
	var events []map[string]any
	emit := func(data json.RawMessage) {
		var e map[string]any
		_ = json.Unmarshal(data, &e)
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}
	_, h := multiSessionPDP(t, &perSubjectI11{}, emit)
	alice := createSession(t, h, "ext-alice")
	bob := createSession(t, h, "ext-bob")
	authorizeIn(t, h, alice)
	authorizeIn(t, h, bob)
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 {
		t.Fatalf("%d events", len(events))
	}
	if events[0]["session_id"] != alice || events[0]["invoking_subject"] != "user:u-alice" {
		t.Errorf("named-session event = %v", events[0])
	}
	if events[1]["session_id"] != bob || events[1]["invoking_subject"] != "user:u-bob" {
		t.Errorf("named-session event = %v", events[1])
	}
}

// TestMultiSessionRevocationFlushesEverySession: installation revocation
// revokes every session and flushes every session's credentials.
func TestMultiSessionRevocationFlushesEverySession(t *testing.T) {
	l, h := multiSessionPDP(t, &perSubjectI11{}, nil)
	alice, bob := createSession(t, h, "ext-alice"), createSession(t, h, "ext-bob")
	l.AfterSync(keiruntime.ErrInstallationRevoked)
	for id, user := range map[string]string{alice: "u-alice", bob: "u-bob"} {
		if _, err := credentialIn(l, id, user); err == nil {
			t.Errorf("session %s still releases a credential after revocation", user)
		}
		if d, r := authorizeIn(t, h, id); d != "deny" || r != "subject_revoked" {
			t.Errorf("session %s after revocation: %s %s", user, d, r)
		}
	}
}
