package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const (
	token   = "fake-oauth-access-token-0001"
	secret  = "fake-shared-secret-value-0001"
	ref     = "kei-prod-connector-0001"
	backend = "aws-secrets-manager"
)

var errBackendDown = errors.New("backend unavailable")

type fakeStore struct {
	values   map[string]string
	calls    int
	deadline bool
}

func (s *fakeStore) Get(ctx context.Context, b, r string) (*string, error) {
	s.calls++
	_, s.deadline = ctx.Deadline()
	if b != backend {
		return nil, fmt.Errorf("wrapped: %w", errBackendDown)
	}
	v, ok := s.values[r]
	if !ok {
		return nil, errors.New("secret not found")
	}
	return &v, nil
}

func resolver(store *fakeStore, now time.Time) Resolver {
	return Resolver{
		Store:              store,
		BackendUnavailable: func(err error) bool { return errors.Is(err, errBackendDown) },
		Now:                func() time.Time { return now },
	}
}

func code(t *testing.T, err error) string {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("error %v is not a *credentials.Error", err)
	}
	if strings.Contains(e.Error(), token) || strings.Contains(e.Error(), secret) || strings.Contains(e.Error(), ref) {
		t.Fatalf("error leaks credential material: %v", e)
	}
	return e.Code
}

func TestSharedSecretResolvesThroughTheStoreWithADeadline(t *testing.T) {
	store := &fakeStore{values: map[string]string{ref: secret}}
	got, err := resolver(store, time.Now()).Resolve(context.Background(), Request{Source: SourceOpaqueRef, Backend: backend, Ref: ref})
	if err != nil || got != secret {
		t.Fatalf("Resolve = %q, %v", got, err)
	}
	if !store.deadline {
		t.Fatal("store lookup had no deadline")
	}
	// An empty source is opaque_ref (v0.1.0 metadata has no source field).
	if got, err := resolver(store, time.Now()).Resolve(context.Background(), Request{Backend: backend, Ref: ref}); err != nil || got != secret {
		t.Fatalf("empty source Resolve = %q, %v", got, err)
	}
}

func TestSharedSecretFailuresDenyWithReasonCodes(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name  string
		store *fakeStore
		req   Request
		want  string
		calls int
	}{
		{"missing secret", &fakeStore{values: map[string]string{}}, Request{Source: SourceOpaqueRef, Backend: backend, Ref: ref}, "credential_unavailable", 1},
		{"empty secret", &fakeStore{values: map[string]string{ref: ""}}, Request{Source: SourceOpaqueRef, Backend: backend, Ref: ref}, "credential_unavailable", 1},
		{"backend down", &fakeStore{}, Request{Source: SourceOpaqueRef, Backend: "gcp-secret-manager", Ref: ref}, "credential_backend_unavailable", 1},
		{"no backend named", &fakeStore{}, Request{Source: SourceOpaqueRef, Ref: ref}, "credential_backend_unavailable", 0},
		{"ref is a url", &fakeStore{}, Request{Source: SourceOpaqueRef, Backend: backend, Ref: "https://vault.example/x"}, "credential_unavailable", 0},
		{"ref is material", &fakeStore{}, Request{Source: SourceOpaqueRef, Backend: backend, Ref: "ghp_abcdef"}, "credential_unavailable", 0},
		{"token on opaque_ref", &fakeStore{values: map[string]string{ref: secret}}, Request{Source: SourceOpaqueRef, Backend: backend, Ref: ref, OAuth: &OAuthToken{AccessToken: token, ExpiresAt: now.Add(time.Minute)}}, "descriptor_invalid", 0},
		{"unknown source", &fakeStore{}, Request{Source: "vault", Backend: backend, Ref: ref}, "descriptor_invalid", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolver(tc.store, now).Resolve(context.Background(), tc.req)
			if got := code(t, err); got != tc.want {
				t.Fatalf("code = %q, want %q", got, tc.want)
			}
			if tc.store.calls != tc.calls {
				t.Fatalf("store calls = %d, want %d", tc.store.calls, tc.calls)
			}
		})
	}
	var nilStore Resolver
	if _, err := nilStore.Resolve(context.Background(), Request{Source: SourceOpaqueRef, Backend: backend, Ref: ref}); code(t, err) != "credential_backend_unavailable" {
		t.Fatal("a resolver without a store must deny")
	}
}

func TestOAuthTokenIsUsedOnlyOverTLSAndBeforeItsUseBy(t *testing.T) {
	now := time.Now()
	fresh := &OAuthToken{AccessToken: token, TokenType: "Bearer", ExpiresAt: now.Add(time.Minute)}
	for _, cp := range []string{"https://kei.example.com", "http://127.0.0.1:8082", "http://localhost:8082", "http://[::1]:8082"} {
		got, err := resolver(&fakeStore{}, now).Resolve(context.Background(), Request{Source: SourceOAuth, OAuth: fresh, ControlPlaneURL: cp})
		if err != nil || got != token {
			t.Fatalf("control plane %s: Resolve = %q, %v", cp, got, err)
		}
	}
	cases := []struct {
		name string
		req  Request
		want string
	}{
		{"plain http", Request{Source: SourceOAuth, OAuth: fresh, ControlPlaneURL: "http://kei.example.com"}, "insecure_transport"},
		{"docker host over http", Request{Source: SourceOAuth, OAuth: fresh, ControlPlaneURL: "http://host.docker.internal:8082"}, "insecure_transport"},
		{"unparseable url", Request{Source: SourceOAuth, OAuth: fresh, ControlPlaneURL: "://"}, "insecure_transport"},
		{"expired", Request{Source: SourceOAuth, OAuth: &OAuthToken{AccessToken: token, ExpiresAt: now}, ControlPlaneURL: "https://kei.example.com"}, "oauth_token_expired"},
		{"no expiry", Request{Source: SourceOAuth, OAuth: &OAuthToken{AccessToken: token}, ControlPlaneURL: "https://kei.example.com"}, "oauth_token_expired"},
		{"no token", Request{Source: SourceOAuth, ControlPlaneURL: "https://kei.example.com"}, "descriptor_invalid"},
		{"empty token", Request{Source: SourceOAuth, OAuth: &OAuthToken{ExpiresAt: now.Add(time.Minute)}, ControlPlaneURL: "https://kei.example.com"}, "descriptor_invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := resolver(&fakeStore{}, now).Resolve(context.Background(), tc.req); code(t, err) != tc.want {
				t.Fatalf("want %s", tc.want)
			}
		})
	}
}

// The two paths never mix: an OAuth connector without a token denies even when
// the store could have produced a value.
func TestOAuthNeverFallsBackToTheSecretStore(t *testing.T) {
	store := &fakeStore{values: map[string]string{ref: secret}}
	_, err := resolver(store, time.Now()).Resolve(context.Background(), Request{Source: SourceOAuth, Backend: backend, Ref: ref, ControlPlaneURL: "https://kei.example.com"})
	if code(t, err) != "descriptor_invalid" || store.calls != 0 {
		t.Fatalf("oauth without a token consulted the store (%d calls)", store.calls)
	}
}

func TestOAuthTokenNeverPrintsOrEncodesTheToken(t *testing.T) {
	var tok OAuthToken
	if err := json.Unmarshal([]byte(`{"access_token":"`+token+`","token_type":"Bearer","expires_at":"2026-09-28T20:00:00Z","account_email_digest":"hmac-sha256:abc"}`), &tok); err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != token || tok.AccountEmailDigest != "hmac-sha256:abc" || tok.ExpiresAt.IsZero() {
		t.Fatalf("decoded = %+v", tok.ExpiresAt)
	}
	encoded, err := json.Marshal(struct{ OAuth *OAuthToken }{&tok})
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{string(encoded), fmt.Sprintf("%v %+v %#v %s", tok, &tok, tok, tok)} {
		if strings.Contains(text, token) {
			t.Fatalf("token leaked: %s", text)
		}
	}
}
