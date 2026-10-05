package credrelease

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testRuntimeToken = "kh_live_runtime_test_token_1234567890"
	testSubjectToken = "subject-token-for-test"
	canary           = "kei-canary-7f3e9b21-credential"
)

// fakeI11 is the identity service's connectorCredentials:resolve. Each call
// is answered by the next entry of replies (the last one repeats).
type fakeI11 struct {
	t       *testing.T
	mu      sync.Mutex
	calls   []resolveRequest
	replies []func(w http.ResponseWriter)
}

func (f *fakeI11) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != ResolvePath {
		f.t.Errorf("I11 got %s %s", r.Method, r.URL.Path)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+testRuntimeToken {
		f.t.Errorf("Authorization = %q", got)
	}
	if got := r.Header.Get("X-Kei-Subject-Token"); got != testSubjectToken {
		f.t.Errorf("X-Kei-Subject-Token = %q", got)
	}
	body, _ := io.ReadAll(r.Body)
	var req resolveRequest
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		f.t.Errorf("I11 body %s: %v", body, err)
	}
	f.mu.Lock()
	f.calls = append(f.calls, req)
	i := len(f.calls) - 1
	if i >= len(f.replies) {
		i = len(f.replies) - 1
	}
	reply := f.replies[i]
	f.mu.Unlock()
	reply(w)
}

func (f *fakeI11) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func credentials(creds map[string]string, failures map[string]string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		type cred struct {
			Provider    string `json:"provider"`
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
		}
		type failure struct {
			Provider string `json:"provider"`
			Reason   string `json:"reason"`
		}
		out := struct {
			Credentials []cred    `json:"credentials"`
			Failures    []failure `json:"failures"`
		}{Credentials: []cred{}, Failures: []failure{}}
		for p, tok := range creds {
			out.Credentials = append(out.Credentials, cred{Provider: p, AccessToken: tok, TokenType: "Bearer"})
		}
		for p, r := range failures {
			out.Failures = append(out.Failures, failure{Provider: p, Reason: r})
		}
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(out)
	}
}

func status(code int) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.WriteHeader(code)
		_, _ = io.WriteString(w, `{"error":{"code":"x","message":"`+canary+`"}}`)
	}
}

func newTestStore(t *testing.T, replies ...func(http.ResponseWriter)) (*Store, *fakeI11) {
	t.Helper()
	f := &fakeI11{t: t, replies: replies}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return NewStore(NewClient(srv.URL, testRuntimeToken, 5*time.Second)), f
}

var errProvider401 = fmt.Errorf("github api: %w", ErrProviderUnauthorized)

func TestStoreMakesExactlyOneI11CallAcrossManyUses(t *testing.T) {
	s, f := newTestStore(t, credentials(map[string]string{"github": canary, "gmail": "gmail-token"}, nil))
	if err := s.Load(context.Background(), testSubjectToken); err != nil {
		t.Fatal(err)
	}
	const n = 50
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			err := s.Use(context.Background(), "github", func(token string) error {
				if token != canary {
					return errors.New("wrong token")
				}
				return nil
			})
			if err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if got := f.count(); got != 1 {
		t.Fatalf("I11 calls = %d across %d uses, want 1", got, n)
	}
	if len(f.calls[0].Providers) != 0 {
		t.Fatalf("session-start I11 named providers %v, want all", f.calls[0].Providers)
	}
}

func TestStoreUnheldProviderDeniesWithoutFetch(t *testing.T) {
	s, f := newTestStore(t, credentials(map[string]string{"github": canary}, map[string]string{"linear": ReasonReconnectRequired}))
	if err := s.Load(context.Background(), testSubjectToken); err != nil {
		t.Fatal(err)
	}
	for provider, want := range map[string]string{"linear": ReasonReconnectRequired, "slack": ReasonNotConnected} {
		called := false
		err := s.Use(context.Background(), provider, func(string) error { called = true; return nil })
		var denied *DeniedError
		if !errors.As(err, &denied) || denied.Reason != want || !denied.Connect() {
			t.Fatalf("%s: err = %v, want connect denial %s", provider, err, want)
		}
		if called {
			t.Fatalf("%s: callback ran without a credential", provider)
		}
	}
	if got := f.count(); got != 1 {
		t.Fatalf("I11 calls = %d, want 1 (no per-use fetch)", got)
	}
}

func TestStoreFlushZeroesAndDrops(t *testing.T) {
	s, f := newTestStore(t, credentials(map[string]string{"github": canary}, nil))
	if err := s.Load(context.Background(), testSubjectToken); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	held := s.tokens["github"]
	s.mu.Unlock()
	s.Flush()
	for _, b := range held {
		if b != 0 {
			t.Fatalf("flushed credential bytes not zeroed: %q", held)
		}
	}
	err := s.Use(context.Background(), "github", func(string) error { t.Fatal("callback ran after flush"); return nil })
	var denied *DeniedError
	if !errors.As(err, &denied) || denied.Reason != ReasonNoSession {
		t.Fatalf("after flush err = %v, want %s", err, ReasonNoSession)
	}
	if s.subjectToken != "" {
		t.Fatal("subject token kept after flush")
	}
	if got := f.count(); got != 1 {
		t.Fatalf("I11 calls = %d, want 1", got)
	}
}

func TestStoreProvider401RefetchesOnceRetriesOnceThenDenies(t *testing.T) {
	s, f := newTestStore(t,
		credentials(map[string]string{"github": "stale-token"}, nil),
		credentials(map[string]string{"github": canary}, nil),
	)
	if err := s.Load(context.Background(), testSubjectToken); err != nil {
		t.Fatal(err)
	}
	var seen []string
	err := s.Use(context.Background(), "github", func(token string) error {
		seen = append(seen, token)
		return errProvider401
	})
	var denied *DeniedError
	if !errors.As(err, &denied) || denied.Reason != ReasonProviderUnauthorized || !denied.Connect() {
		t.Fatalf("err = %v, want connect denial %s", err, ReasonProviderUnauthorized)
	}
	if len(seen) != 2 || seen[0] != "stale-token" || seen[1] != canary {
		t.Fatalf("callback tokens = %d calls, want stale then re-fetched", len(seen))
	}
	if got := f.count(); got != 2 {
		t.Fatalf("I11 calls = %d, want 2 (start + one re-fetch)", got)
	}
	if p := f.calls[1].Providers; len(p) != 1 || p[0] != "github" {
		t.Fatalf("re-fetch providers = %v, want [github]", p)
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatal("denial error carries the credential")
	}
}

func TestStoreProvider401RefetchSucceedsAndRetrySucceeds(t *testing.T) {
	s, f := newTestStore(t,
		credentials(map[string]string{"github": "stale-token"}, nil),
		credentials(map[string]string{"github": canary}, nil),
	)
	if err := s.Load(context.Background(), testSubjectToken); err != nil {
		t.Fatal(err)
	}
	err := s.Use(context.Background(), "github", func(token string) error {
		if token == "stale-token" {
			return errProvider401
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The re-fetched credential is now held; later uses do not fetch.
	if err := s.Use(context.Background(), "github", func(token string) error {
		if token != canary {
			return errors.New("re-fetched credential not held")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := f.count(); got != 2 {
		t.Fatalf("I11 calls = %d, want 2", got)
	}
}

func TestStoreProvider401RefetchFailureDenies(t *testing.T) {
	for name, reply := range map[string]func(http.ResponseWriter){
		ReasonReconnectRequired: credentials(nil, map[string]string{"github": ReasonReconnectRequired}),
		"UNAUTHENTICATED":       status(http.StatusUnauthorized),
		"SUBJECT_UNLINKED":      status(http.StatusForbidden),
		"UNAVAILABLE":           status(http.StatusServiceUnavailable),
	} {
		t.Run(name, func(t *testing.T) {
			s, f := newTestStore(t, credentials(map[string]string{"github": canary}, nil), reply)
			if err := s.Load(context.Background(), testSubjectToken); err != nil {
				t.Fatal(err)
			}
			calls := 0
			err := s.Use(context.Background(), "github", func(string) error { calls++; return errProvider401 })
			var denied *DeniedError
			if !errors.As(err, &denied) || denied.Reason != name {
				t.Fatalf("err = %v, want denial %s", err, name)
			}
			if calls != 1 {
				t.Fatalf("callback ran %d times, want 1 (no retry after a failed re-fetch)", calls)
			}
			// The rejected credential is gone and is not fetched again.
			_ = s.Use(context.Background(), "github", func(string) error { t.Fatal("callback ran"); return nil })
			if got := f.count(); got != 2 {
				t.Fatalf("I11 calls = %d, want 2", got)
			}
			if strings.Contains(err.Error(), canary) {
				t.Fatal("denial error carries I11 body")
			}
		})
	}
}

func TestStoreNon401CallbackErrorIsNotRetried(t *testing.T) {
	s, f := newTestStore(t, credentials(map[string]string{"github": canary}, nil))
	if err := s.Load(context.Background(), testSubjectToken); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("provider 500")
	calls := 0
	if err := s.Use(context.Background(), "github", func(string) error { calls++; return boom }); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if calls != 1 || f.count() != 1 {
		t.Fatalf("callback calls = %d, I11 calls = %d; want 1, 1", calls, f.count())
	}
}

func TestStoreLoadErrorsDenyAndNeverCarryBody(t *testing.T) {
	for code, want := range map[int]error{
		http.StatusUnauthorized:        ErrUnauthenticated,
		http.StatusForbidden:           ErrSubjectUnlinked,
		http.StatusBadRequest:          ErrUnavailable,
		http.StatusServiceUnavailable:  ErrUnavailable,
		http.StatusInternalServerError: ErrUnavailable,
	} {
		s, _ := newTestStore(t, status(code))
		err := s.Load(context.Background(), testSubjectToken)
		if !errors.Is(err, want) {
			t.Fatalf("%d: err = %v, want %v", code, err, want)
		}
		if strings.Contains(err.Error(), canary) {
			t.Fatalf("%d: load error carries I11 body", code)
		}
		var denied *DeniedError
		if err := s.Use(context.Background(), "github", func(string) error { return nil }); !errors.As(err, &denied) || denied.Connect() {
			t.Fatalf("%d: use err = %v, want non-connect denial", code, err)
		}
	}
}

func TestStoreMalformedResponseDoesNotLeak(t *testing.T) {
	s, _ := newTestStore(t, func(w http.ResponseWriter) {
		_, _ = io.WriteString(w, `{"credentials":[{"provider":"github","access_token":"`+canary+`"`)
	})
	err := s.Load(context.Background(), testSubjectToken)
	if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), canary) {
		t.Fatalf("err = %v", err)
	}
}

func TestStoreFlushDuringLoadDiscardsResult(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})
	s, _ := newTestStore(t, func(w http.ResponseWriter) {
		close(entered)
		<-release
		credentials(map[string]string{"github": canary}, nil)(w)
	})
	done := make(chan error, 1)
	go func() { done <- s.Load(context.Background(), testSubjectToken) }()
	<-entered
	s.Flush()
	close(release)
	if err := <-done; err == nil {
		t.Fatal("load after flush reported success")
	}
	if err := s.Use(context.Background(), "github", func(string) error { t.Fatal("callback ran"); return nil }); err == nil {
		t.Fatal("credential installed after flush")
	}
}
