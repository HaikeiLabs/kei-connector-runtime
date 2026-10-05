package credrelease

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// ErrProviderUnauthorized is what a Use callback returns (or wraps) when the
// provider answered 401 with the held credential. It triggers the one
// single-provider re-fetch and one retry the owner allowed (ADR-034 expiry
// retry); every other callback error is returned as is.
var ErrProviderUnauthorized = errors.New("credrelease: provider rejected the credential")

// ReasonProviderUnauthorized is the deny reason when the retried call still
// got a provider 401. It is never re-fetched again.
const ReasonProviderUnauthorized = "PROVIDER_UNAUTHORIZED"

// ReasonNoSession is the deny reason when no linked session holds credentials.
const ReasonNoSession = "NO_SESSION"

// DeniedError is a connect/deny decision for one provider: the session has no
// usable credential for it. It never carries credential material.
type DeniedError struct {
	Provider string
	Reason   string // an I11 failure reason or one of the Reason* constants
}

func (e *DeniedError) Error() string {
	return fmt.Sprintf("credrelease: no usable credential for provider %q (%s)", e.Provider, e.Reason)
}

// Connect reports whether the subject can fix the denial by (re)connecting
// the provider, rather than it being an identity or availability failure.
func (e *DeniedError) Connect() bool {
	switch e.Reason {
	case ReasonNotConnected, ReasonReconnectRequired, ReasonMaxLifetimeExceeded, ReasonProviderUnauthorized:
		return true
	}
	return false
}

// resolver is the I11 call the store makes; *Client implements it.
type resolver interface {
	resolve(ctx context.Context, subjectToken string, providers []string) (resolved, error)
}

// Store holds one session's connector credentials in the serve daemon's
// memory. Load fetches them once at linked session start; Flush zeroes and
// drops them at session end. Values reach code only through Use.
type Store struct {
	client resolver

	mu           sync.Mutex
	gen          uint64 // bumped by Flush and Load; a stale fetch is discarded
	subject      string // the session subject (user id) the credentials belong to
	subjectToken string
	tokens       map[string][]byte
	failures     map[string]string
	loadErr      error
}

// NewStore returns an empty store that fetches through client.
func NewStore(client *Client) *Store {
	return &Store{client: client}
}

// Load flushes any held credentials and makes the session's one I11 call
// for subject (the session's user id) with subjectToken. On error the store
// stays empty, and every Use denies until the next Load. A Flush during the
// call discards its result.
func (s *Store) Load(ctx context.Context, subject, subjectToken string) error {
	s.mu.Lock()
	s.flushLocked()
	gen := s.gen
	s.mu.Unlock()

	res, err := s.client.resolve(ctx, subjectToken, nil)

	s.mu.Lock()
	defer s.mu.Unlock()
	if gen != s.gen {
		zeroAll(res.tokens)
		return errors.New("credrelease: session ended while loading credentials")
	}
	if err != nil {
		s.loadErr = err
		return err
	}
	s.subject, s.subjectToken = subject, subjectToken
	s.tokens, s.failures = res.tokens, res.failures
	return nil
}

// Flush zeroes and drops every held credential and the subject token.
func (s *Store) Flush() {
	s.mu.Lock()
	s.flushLocked()
	s.mu.Unlock()
}

func (s *Store) flushLocked() {
	s.gen++
	zeroAll(s.tokens)
	s.tokens, s.failures, s.subject, s.subjectToken, s.loadErr = nil, nil, "", "", nil
}

// Use runs fn with the session's credential for provider, if the held
// credentials belong to subject; a caller passes the subject its decision was
// made for, so a session that changed since then denies. The token is a copy
// and fn must not retain or return it. If fn reports ErrProviderUnauthorized,
// Use re-fetches that one provider through I11, retries fn once, and returns
// a *DeniedError if the re-fetch or the retry fails. There is no other fetch.
func (s *Store) Use(ctx context.Context, subject, provider string, fn func(token string) error) error {
	token, gen, err := s.take(subject, provider)
	if err != nil {
		return err
	}
	err = fn(token)
	if !errors.Is(err, ErrProviderUnauthorized) {
		return err
	}
	if token, err = s.refetch(ctx, provider, gen); err != nil {
		return err
	}
	err = fn(token)
	if errors.Is(err, ErrProviderUnauthorized) {
		// The re-fetched credential was rejected too. Drop it so no later
		// use loops through another re-fetch; the session must reconnect.
		s.reject(provider, gen)
		return &DeniedError{Provider: provider, Reason: ReasonProviderUnauthorized}
	}
	return err
}

// reject drops provider's credential after a 401 on the retried call and
// records the denial, unless the session changed since gen.
func (s *Store) reject(provider string, gen uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen != gen {
		return
	}
	if old, ok := s.tokens[provider]; ok {
		zero(old)
		delete(s.tokens, provider)
	}
	if s.failures == nil {
		s.failures = map[string]string{}
	}
	s.failures[provider] = ReasonProviderUnauthorized
}

func (s *Store) take(subject, provider string) (string, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if subject == "" || (s.subject != subject && s.loadErr == nil) {
		return "", s.gen, &DeniedError{Provider: provider, Reason: ReasonNoSession}
	}
	if b, ok := s.tokens[provider]; ok {
		return string(b), s.gen, nil
	}
	return "", s.gen, s.deniedLocked(provider)
}

func (s *Store) deniedLocked(provider string) error {
	switch {
	case s.loadErr != nil:
		return &DeniedError{Provider: provider, Reason: errorReason(s.loadErr)}
	case s.subjectToken == "":
		return &DeniedError{Provider: provider, Reason: ReasonNoSession}
	case s.failures[provider] != "":
		return &DeniedError{Provider: provider, Reason: s.failures[provider]}
	}
	return &DeniedError{Provider: provider, Reason: ReasonNotConnected}
}

// refetch makes the single-provider I11 call after a provider 401 and swaps in
// the new credential, unless the session changed since gen.
func (s *Store) refetch(ctx context.Context, provider string, gen uint64) (string, error) {
	s.mu.Lock()
	subjectToken := s.subjectToken
	current := s.gen == gen && subjectToken != ""
	s.mu.Unlock()
	if !current {
		return "", &DeniedError{Provider: provider, Reason: ReasonNoSession}
	}

	res, err := s.client.resolve(ctx, subjectToken, []string{provider})
	defer zeroAll(res.tokens)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen != gen {
		return "", &DeniedError{Provider: provider, Reason: ReasonNoSession}
	}
	if old, ok := s.tokens[provider]; ok {
		zero(old)
		delete(s.tokens, provider)
	}
	if s.failures == nil {
		s.failures = map[string]string{}
	}
	if err != nil {
		s.failures[provider] = errorReason(err)
		return "", &DeniedError{Provider: provider, Reason: s.failures[provider]}
	}
	b, ok := res.tokens[provider]
	if !ok {
		reason := res.failures[provider]
		if reason == "" {
			reason = ReasonNotConnected
		}
		s.failures[provider] = reason
		return "", &DeniedError{Provider: provider, Reason: reason}
	}
	s.tokens[provider] = append([]byte(nil), b...)
	delete(s.failures, provider)
	return string(b), nil
}

func errorReason(err error) string {
	switch {
	case errors.Is(err, ErrUnauthenticated):
		return "UNAUTHENTICATED"
	case errors.Is(err, ErrSubjectUnlinked):
		return "SUBJECT_UNLINKED"
	}
	return "UNAVAILABLE"
}

func zeroAll(m map[string][]byte) {
	for _, b := range m {
		zero(b)
	}
}
