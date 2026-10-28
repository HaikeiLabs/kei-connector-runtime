package runtime_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	connectorruntime "github.com/HaikeiLabs/kei-connector-runtime"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/credrelease"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

// sessionI11 is a fake identity service that records the subject token of
// each connectorCredentials:resolve call and returns one github credential.
type sessionI11 struct {
	mu       sync.Mutex
	subjects []string
}

func (f *sessionI11) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.subjects = append(f.subjects, r.Header.Get("X-Kei-Subject-Token"))
	f.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{
		"credentials": []map[string]string{{"provider": "github", "access_token": "gh-session-token", "token_type": "Bearer"}},
	})
}

func (f *sessionI11) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.subjects...)
}

func newCredentialPDP(t *testing.T, stateDir string) (*keiruntime.LocalPDP, *sessionI11) {
	t.Helper()
	f := &sessionI11{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           policyTestToken,
		RuntimeControlPlaneURL: "https://kei.example",
		RuntimeStateDir:        stateDir,
	}, nil)
	l.SetCredentialStore(credrelease.NewStore(credrelease.NewClient(srv.URL, policyTestToken, 5*time.Second)))
	return l, f
}

// requireHeld asserts the session holds the github credential.
func requireHeld(t *testing.T, l *keiruntime.LocalPDP, sessionID, subject string) {
	t.Helper()
	err := l.UseCredential(context.Background(), sessionID, subject, "github", func(token string) error {
		if token != "gh-session-token" {
			return errors.New("unexpected credential")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("credential not held: %v", err)
	}
}

// requireFlushed asserts the session holds no credential.
func requireFlushed(t *testing.T, l *keiruntime.LocalPDP, sessionID, subject string) {
	t.Helper()
	err := l.UseCredential(context.Background(), sessionID, subject, "github", func(string) error {
		t.Fatal("callback ran with a flushed credential")
		return nil
	})
	var denied *credrelease.DeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("err = %v, want a denial", err)
	}
}

func TestSessionCredentialsFetchedOnceForLinkedCLISession(t *testing.T) {
	l, f := newCredentialPDP(t, t.TempDir())
	l.SetKeychain(&fakeKeychain{token: "cli-subject-token", userID: "u-1"})
	h := sessionHandler(t, l)

	id := startNamedSession(t, h, `{"schema":"kei.session/v2","source":"cli"}`)
	for range 20 {
		requireHeld(t, l, id, "u-1")
	}
	if got := f.calls(); len(got) != 1 || got[0] != "cli-subject-token" {
		t.Fatalf("I11 calls = %v, want one with the cli token", got)
	}
}

func TestSessionCredentialsFlushOnEveryEndPath(t *testing.T) {
	ends := map[string]func(t *testing.T, l *keiruntime.LocalPDP, h http.Handler, id string){
		"DELETE /v1/session": func(t *testing.T, _ *keiruntime.LocalPDP, h http.Handler, id string) {
			rec := sessionRequest(h, http.MethodDelete, "/v1/session", id, "")
			if rec.Code != http.StatusNoContent {
				t.Fatalf("DELETE = %d", rec.Code)
			}
		},
		"daemon Close": func(_ *testing.T, l *keiruntime.LocalPDP, _ http.Handler, _ string) {
			l.Close()
		},
		"installation revoked": func(_ *testing.T, l *keiruntime.LocalPDP, _ http.Handler, _ string) {
			l.AfterSync(keiruntime.ErrInstallationRevoked)
		},
	}
	for name, end := range ends {
		t.Run(name, func(t *testing.T) {
			l, f := newCredentialPDP(t, t.TempDir())
			l.SetKeychain(&fakeKeychain{token: "cli-subject-token", userID: "u-1"})
			h := sessionHandler(t, l)
			id := startNamedSession(t, h, `{"schema":"kei.session/v2","source":"cli"}`)
			requireHeld(t, l, id, "u-1")
			end(t, l, h, id)
			requireFlushed(t, l, id, "u-1")
			if got := len(f.calls()); got != 1 {
				t.Fatalf("I11 calls = %d, want 1 (no fetch after the session ended)", got)
			}
		})
	}
}

func TestSessionCredentialsNewLinkedPUTReplacesCredentials(t *testing.T) {
	l, f := newCredentialPDP(t, t.TempDir())
	kc := &fakeKeychain{token: "first-token", userID: "u-1"}
	l.SetKeychain(kc)
	h := sessionHandler(t, l)
	first := startNamedSession(t, h, `{"schema":"kei.session/v2","source":"cli"}`)
	kc.token = "second-token"
	second := startNamedSession(t, h, `{"schema":"kei.session/v2","source":"cli"}`)
	requireHeld(t, l, first, "u-1")
	requireHeld(t, l, second, "u-1")
	if got := f.calls(); len(got) != 2 || got[0] != "first-token" || got[1] != "second-token" {
		t.Fatalf("I11 subject tokens = %v", got)
	}
}

func TestSessionCredentialsBundleIdentityUsesItsSubjectToken(t *testing.T) {
	dir := t.TempDir()
	activateBundle(t, dir, bundleWithIdentities(t, []policybundle.Identity{
		{Source: "discord", ExternalID: "ext-linked", UserID: "u-alice", Status: "linked", SubjectToken: "es256-subject-alice"},
		{Source: "discord", ExternalID: "ext-pending", UserID: "u-bob", Status: "pending", SubjectToken: "es256-subject-bob"},
	}))
	l, f := newCredentialPDP(t, dir)
	l.SetIdentity(&keiruntime.Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001")})
	h := sessionHandler(t, l)

	pending := startNamedSession(t, h, `{"schema":"kei.session/v2","source":"discord","external_id":"ext-pending"}`)
	if got := f.calls(); len(got) != 0 {
		t.Fatalf("non-linked subject fetched credentials: %v", got)
	}
	requireFlushed(t, l, pending, "u-bob")

	linked := startNamedSession(t, h, `{"schema":"kei.session/v2","source":"discord","external_id":"ext-linked"}`)
	requireHeld(t, l, linked, "u-alice")
	if got := f.calls(); len(got) != 1 || got[0] != "es256-subject-alice" {
		t.Fatalf("I11 subject tokens = %v", got)
	}
}

func TestSessionCredentialsReconcileRevocationFlushes(t *testing.T) {
	dir := t.TempDir()
	activateBundle(t, dir, bundleWithIdentities(t, []policybundle.Identity{
		{Source: "discord", ExternalID: "ext-linked", UserID: "u-alice", Status: "linked", SubjectToken: "es256-subject-alice"},
	}))
	l, _ := newCredentialPDP(t, dir)
	l.SetIdentity(&keiruntime.Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001")})
	h := sessionHandler(t, l)
	id := startNamedSession(t, h, `{"schema":"kei.session/v2","source":"discord","external_id":"ext-linked"}`)
	requireHeld(t, l, id, "u-alice")

	// The next bundle no longer grants the subject.
	next := bundleWithIdentities(t, []policybundle.Identity{
		{Source: "discord", ExternalID: "ext-linked", UserID: "u-alice", Status: "revoked"},
	})
	activateBundle(t, dir, bytes.Replace(next, []byte(`"bundle_version":1`), []byte(`"bundle_version":2`), 1))
	l.AfterSync(nil)
	requireFlushed(t, l, id, "u-alice")
}

func TestSessionCredentialsLegacyModeNeverFetches(t *testing.T) {
	f := &sessionI11{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	l := keiruntime.NewLocalPDP(connectorruntime.Config{RuntimeToken: policyTestToken, RuntimeControlPlaneURL: srv.URL}, nil)
	l.SetKeychain(&fakeKeychain{token: "cli-subject-token", userID: "u-1"})
	h := sessionHandler(t, l)
	id := startNamedSession(t, h, `{"schema":"kei.session/v2","source":"cli"}`)
	if err := l.UseCredential(context.Background(), id, "u-1", "github", func(string) error { return nil }); err == nil {
		t.Fatal("legacy mode served a session credential")
	}
	if got := f.calls(); len(got) != 0 {
		t.Fatalf("legacy mode made I11 calls: %v", got)
	}
}
