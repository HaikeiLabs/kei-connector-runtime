package credrelease

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// HAI-577 (kei-oidc-bridge #69): one connector's token for one resource,
// POST /api/v1/connectorCredentials/{connector}:resolve {"resource": "..."}.
// The bridge echoes connector_id, issuer, resource and account_model, and
// answers a token for another audience with AUDIENCE_MISMATCH.

const (
	testConnector = "aaaaaaaa-0000-4000-8000-00000000000a"
	testResource  = "https://mcp.example.com/mcp"
)

type fakeConnectorResolve struct {
	t       *testing.T
	mu      sync.Mutex
	calls   []string // connector|resource
	replies []func(w http.ResponseWriter, connector, resource string)
}

func (f *fakeConnectorResolve) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	connector, ok := strings.CutPrefix(r.URL.Path, "/api/v1/connectorCredentials/")
	connector, ok2 := strings.CutSuffix(connector, ":resolve")
	if r.Method != http.MethodPost || !ok || !ok2 {
		f.t.Errorf("bridge got %s %s", r.Method, r.URL.Path)
	}
	if r.Header.Get("Authorization") != "Bearer "+testRuntimeToken || r.Header.Get("X-Kei-Subject-Token") != testSubjectToken {
		f.t.Errorf("auth headers %q / %q", r.Header.Get("Authorization"), r.Header.Get("X-Kei-Subject-Token"))
	}
	var body struct {
		Resource string `json:"resource"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		f.t.Errorf("body: %v", err)
	}
	f.mu.Lock()
	f.calls = append(f.calls, connector+"|"+body.Resource)
	i := min(len(f.calls)-1, len(f.replies)-1)
	reply := f.replies[i]
	f.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	reply(w, connector, body.Resource)
}

func (f *fakeConnectorResolve) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func released(token string) func(http.ResponseWriter, string, string) {
	return func(w http.ResponseWriter, connector, resource string) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"connector_id": connector, "issuer": "https://auth.example.com", "resource": resource, "account_model": "per_user",
			"credential": map[string]any{"access_token": token, "token_type": "Bearer", "expire_time": "2026-10-14T20:00:00Z", "scopes": []string{"read"}},
		})
	}
}

func failed(reason string) func(http.ResponseWriter, string, string) {
	return func(w http.ResponseWriter, connector, resource string) {
		_ = json.NewEncoder(w).Encode(map[string]any{"connector_id": connector, "resource": resource, "failure": map[string]any{"reason": reason}})
	}
}

func bridgeStatus(code int) func(http.ResponseWriter, string, string) {
	return func(w http.ResponseWriter, _, _ string) {
		w.WriteHeader(code)
		_, _ = io.WriteString(w, `{"error":{"message":"`+canary+`"}}`)
	}
}

// loadedStore is a session store whose subject token is held (as after a
// linked session start), resolving connector credentials from bridge.
func loadedStore(t *testing.T, bridge *fakeConnectorResolve) *Store {
	t.Helper()
	mux := http.NewServeMux()
	load := credentials(nil, nil)
	mux.HandleFunc(ResolvePath, func(w http.ResponseWriter, _ *http.Request) { load(w) })
	mux.Handle("/api/v1/connectorCredentials/", bridge)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	s := NewStore(NewClient(srv.URL, testRuntimeToken, 5*time.Second))
	if err := s.Load(context.Background(), testSubject, testSubjectToken); err != nil {
		t.Fatal(err)
	}
	return s
}

func useConnector(s *Store, subject, resource string) (ConnectorCredential, error) {
	var got ConnectorCredential
	err := s.UseConnector(context.Background(), subject, testConnector, resource, func(c ConnectorCredential) error {
		got = c
		return nil
	})
	return got, err
}

func TestUseConnectorReleasesTheConnectorsToken(t *testing.T) {
	bridge := &fakeConnectorResolve{t: t, replies: []func(http.ResponseWriter, string, string){released(canary)}}
	s := loadedStore(t, bridge)

	got, err := useConnector(s, testSubject, testResource)
	if err != nil {
		t.Fatal(err)
	}
	want := ConnectorCredential{ConnectorID: testConnector, Issuer: "https://auth.example.com", Resource: testResource, AccountModel: "per_user", AccessToken: canary}
	if got != want {
		t.Fatalf("credential = %+v, want %+v", got, want)
	}
	if bridge.calls[0] != testConnector+"|"+testResource {
		t.Fatalf("requested %v", bridge.calls)
	}
}

func TestUseConnectorCachesPerConnectorAndResource(t *testing.T) {
	bridge := &fakeConnectorResolve{t: t, replies: []func(http.ResponseWriter, string, string){released(canary)}}
	s := loadedStore(t, bridge)

	for i := 0; i < 3; i++ {
		if _, err := useConnector(s, testSubject, testResource); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := useConnector(s, testSubject, "https://other.example.com/mcp"); err != nil {
		t.Fatal(err)
	}
	if bridge.count() != 2 {
		t.Fatalf("bridge calls = %d, want one per (connector, resource)", bridge.count())
	}
}

func TestUseConnectorFailures(t *testing.T) {
	for _, reason := range []string{ReasonAudienceMismatch, ReasonNotConnected, ReasonReconnectRequired, ReasonProviderUnavailable} {
		bridge := &fakeConnectorResolve{t: t, replies: []func(http.ResponseWriter, string, string){failed(reason), released(canary)}}
		s := loadedStore(t, bridge)

		_, err := useConnector(s, testSubject, testResource)
		var denied *DeniedError
		if !errors.As(err, &denied) || denied.Reason != reason {
			t.Fatalf("%s: err = %v", reason, err)
		}
		// A failure is not cached: once connected, the next use succeeds.
		if _, err := useConnector(s, testSubject, testResource); err != nil {
			t.Fatalf("%s: retry after the failure: %v", reason, err)
		}
	}
}

func TestUseConnectorDropForgetsTheCachedToken(t *testing.T) {
	bridge := &fakeConnectorResolve{t: t, replies: []func(http.ResponseWriter, string, string){released(canary)}}
	s := loadedStore(t, bridge)

	_, _ = useConnector(s, testSubject, testResource)
	s.DropConnector(testConnector, testResource)
	_, _ = useConnector(s, testSubject, testResource)

	if bridge.count() != 2 {
		t.Fatalf("bridge calls = %d, want a re-resolve after the drop", bridge.count())
	}
}

func TestUseConnectorDeniesWithoutTheSessionSubject(t *testing.T) {
	bridge := &fakeConnectorResolve{t: t, replies: []func(http.ResponseWriter, string, string){released(canary)}}
	s := loadedStore(t, bridge)

	if _, err := useConnector(s, "someone-else", testResource); err == nil {
		t.Fatal("another subject got the session's connector credential")
	}
	s.Flush()
	if _, err := useConnector(s, testSubject, testResource); err == nil {
		t.Fatal("a flushed session still released a credential")
	}
	if bridge.count() != 0 {
		t.Fatalf("bridge calls = %d, want none", bridge.count())
	}
}

func TestUseConnectorFlushZeroesTheCachedToken(t *testing.T) {
	bridge := &fakeConnectorResolve{t: t, replies: []func(http.ResponseWriter, string, string){released(canary)}}
	s := loadedStore(t, bridge)
	_, _ = useConnector(s, testSubject, testResource)

	s.mu.Lock()
	held := s.connectorTokens[testConnector+"|"+testResource].token
	s.mu.Unlock()
	s.Flush()
	if string(held) == canary {
		t.Fatal("Flush left the connector token in memory")
	}
}

func TestUseConnectorBridgeErrorsNeverCarryTheBody(t *testing.T) {
	for code, want := range map[int]error{http.StatusUnauthorized: ErrUnauthenticated, http.StatusForbidden: ErrSubjectUnlinked, http.StatusServiceUnavailable: ErrUnavailable, http.StatusBadRequest: ErrUnavailable} {
		bridge := &fakeConnectorResolve{t: t, replies: []func(http.ResponseWriter, string, string){bridgeStatus(code)}}
		s := loadedStore(t, bridge)
		_, err := useConnector(s, testSubject, testResource)
		if !errors.Is(err, want) {
			t.Errorf("status %d: err = %v, want %v", code, err, want)
		}
		if err != nil && strings.Contains(err.Error(), canary) {
			t.Errorf("status %d: error carries the response body", code)
		}
	}
}

func TestUseConnectorRefusesANonBearerToken(t *testing.T) {
	bridge := &fakeConnectorResolve{t: t, replies: []func(http.ResponseWriter, string, string){func(w http.ResponseWriter, c, r string) {
		_ = json.NewEncoder(w).Encode(map[string]any{"connector_id": c, "issuer": "i", "resource": r, "account_model": "per_user", "credential": map[string]any{"access_token": canary, "token_type": "MAC"}})
	}}}
	s := loadedStore(t, bridge)
	if _, err := useConnector(s, testSubject, testResource); err == nil {
		t.Fatal("a non-Bearer token was released")
	}
}
