package pdp

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

// Status is a session subject's identity outcome (ADR-026 G0).
type Status string

const (
	StatusLinked         Status = policybundle.SubjectLinked
	StatusUnlinked       Status = policybundle.SubjectUnlinked
	StatusPending        Status = policybundle.SubjectPending
	StatusCrossWorkspace Status = policybundle.SubjectCrossWorkspace
	// StatusRevoked is set only by the runtime, never by Start.
	StatusRevoked Status = policybundle.SubjectRevoked
)

// Subject is the acting user of a worker session, from machine login plus
// kei or harness login. Enrollment is the private link returned only on a
// subject_unlinked denial. Token holds the CLI login token for cli sessions.
type Subject struct {
	UserID     string
	Email      string
	Source     string
	ExternalID string
	Groups     []string
	Status     Status
	Enrollment json.RawMessage
	Token      string
}

// DefaultSession is the session id of the legacy default session: requests
// that name no session use it. Deprecated: name a session created with
// Create; the default session goes away after one release.
const DefaultSession = ""

// ReasonSessionNotFound is the deny reason for a session id that was never
// created, has ended, or expired.
const ReasonSessionNotFound = "session_not_found"

// ReasonSessionRevalidationRequired is the deny reason for a session whose
// max age was exceeded and was recycled.
const ReasonSessionRevalidationRequired = "session_revalidation_required"

// SessionMaxAge is how long a named session lives before it must be
// revalidated. See ADR-026 G0.
const SessionMaxAge = 8 * time.Hour

// Sessions holds worker sessions in memory only: the legacy default session
// and any number of sessions named by an opaque id (owner decision
// 2026-10-06: many agents in parallel on one machine). Nothing is persisted;
// a session ends with End, idle expiry, a revocation, or the process.
//
// Id sessions are independent: each has its own lock, and the registry is a
// sync.Map, so concurrent calls on different sessions never wait on each
// other. There is no session cap; the limit is the host.
type Sessions struct {
	// The legacy default session.
	mu  sync.RWMutex
	cur *Subject

	byID     sync.Map // id -> *idSession
	idleTTL  atomic.Int64
	now      func() time.Time
	onEnd    atomic.Pointer[func(id string)]
	onReuse  atomic.Pointer[func(id string)] // recycle (max age) only
	recycled sync.Map                        // id -> struct{}; consumed by the next sessionLive check
}

type idSession struct {
	mu        sync.RWMutex
	sub       Subject
	pinned    bool
	startedAt int64        // unix nanoseconds, set at creation
	lastUsed  atomic.Int64 // unix nanoseconds
}

// DefaultIdleTTL is how long an id session lives without use.
const DefaultIdleTTL = 30 * time.Minute

func NewSessions() *Sessions {
	s := &Sessions{now: time.Now}
	s.idleTTL.Store(int64(DefaultIdleTTL))
	return s
}

// SetNow replaces the time source (for tests). A nil fn panics on use.
func (s *Sessions) SetNow(fn func() time.Time) { s.now = fn }

// SetIdleTTL sets how long an id session lives without use (> 0). The
// default session never expires.
func (s *Sessions) SetIdleTTL(d time.Duration) {
	if d > 0 {
		s.idleTTL.Store(int64(d))
	}
}

// IdleTTL is the current idle lifetime of an id session.
func (s *Sessions) IdleTTL() time.Duration { return time.Duration(s.idleTTL.Load()) }

// OnEnd registers fn to run, once per session, when an id session ends for
// any reason (EndID, idle expiry, Sweep), so its owner can drop what it held
// for it. fn runs on the ending goroutine and must not block.
func (s *Sessions) OnEnd(fn func(id string)) { s.onEnd.Store(&fn) }

// OnRecycle registers fn to run when a session is ended because its max age
// was exceeded. The runtime uses this to emit a session_recycled lifecycle
// event. fn runs on the ending goroutine and must not block.
func (s *Sessions) OnRecycle(fn func(id string)) { s.onReuse.Store(&fn) }

func validSubject(sub Subject) (Subject, error) {
	switch sub.Status {
	case StatusLinked:
		if sub.UserID == "" {
			return Subject{}, errors.New("pdp: a linked session subject requires a user id")
		}
	case StatusUnlinked, StatusPending, StatusCrossWorkspace, StatusRevoked:
	default:
		return Subject{}, errors.New("pdp: session status must be linked, unlinked, pending, cross_workspace or revoked")
	}
	if sub.Status != StatusUnlinked {
		sub.Enrollment = nil
	}
	sub.Enrollment = append(json.RawMessage(nil), sub.Enrollment...)
	return sub, nil
}

func copySubject(sub Subject) Subject {
	sub.Enrollment = append(json.RawMessage(nil), sub.Enrollment...)
	sub.Groups = append([]string(nil), sub.Groups...)
	return sub
}

// Start begins the legacy default session, replacing any previous one.
func (s *Sessions) Start(sub Subject) error {
	sub, err := validSubject(sub)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.cur = &sub
	s.mu.Unlock()
	return nil
}

// End ends the legacy default session; later calls without a session id
// have no session subject.
func (s *Sessions) End() {
	s.mu.Lock()
	s.cur = nil
	s.mu.Unlock()
}

// Current returns a copy of the legacy default session's subject.
func (s *Sessions) Current() (Subject, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cur == nil {
		return Subject{}, false
	}
	return copySubject(*s.cur), true
}

// Create starts a new session for sub and returns its id: "ks_" and 32
// random bytes, base64url. Sessions created this way are independent of each
// other and of the default session.
func (s *Sessions) Create(sub Subject) (string, error) { return s.create(sub, false) }

// CreatePinned creates a named session that does not expire from idleness.
// It is intended for daemon-owned identities that are explicitly ended when
// their authoritative source changes.
func (s *Sessions) CreatePinned(sub Subject) (string, error) { return s.create(sub, true) }

func (s *Sessions) create(sub Subject, pinned bool) (string, error) {
	sub, err := validSubject(sub)
	if err != nil {
		return "", err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	now := s.now()
	id := "ks_" + base64.RawURLEncoding.EncodeToString(b)
	e := &idSession{sub: sub, pinned: pinned, startedAt: now.UnixNano()}
	e.lastUsed.Store(now.UnixNano())
	s.byID.Store(id, e)
	return id, nil
}

// Get returns a copy of the subject of session id and marks the session used.
// DefaultSession reads the default session. An unknown, ended or idle-expired
// id is not found; an expired one ends here.
func (s *Sessions) Get(id string) (Subject, bool) {
	if id == DefaultSession {
		return s.Current()
	}
	e, ok := s.live(id)
	if !ok {
		return Subject{}, false
	}
	e.lastUsed.Store(s.now().UnixNano())
	e.mu.RLock()
	defer e.mu.RUnlock()
	return copySubject(e.sub), true
}

// Exists reports whether session id is live, without marking it used.
func (s *Sessions) Exists(id string) bool {
	if id == DefaultSession {
		_, ok := s.Current()
		return ok
	}
	_, ok := s.live(id)
	return ok
}

func (s *Sessions) live(id string) (*idSession, bool) {
	v, ok := s.byID.Load(id)
	if !ok {
		return nil, false
	}
	e := v.(*idSession)
	now := s.now()
	if maxAge := s.maxAgeExpired(e, now); maxAge {
		s.recycled.Store(id, struct{}{})
		s.endID(id, e)
		if fn := s.onReuse.Load(); fn != nil {
			(*fn)(id)
		}
		return nil, false
	}
	if s.expired(e, now) {
		s.endID(id, e)
		return nil, false
	}
	return e, true
}

func (s *Sessions) expired(e *idSession, now time.Time) bool {
	return !e.pinned && now.Sub(time.Unix(0, e.lastUsed.Load())) >= s.IdleTTL()
}

func (s *Sessions) maxAgeExpired(e *idSession, now time.Time) bool {
	return !e.pinned && now.Sub(time.Unix(0, e.startedAt)) >= SessionMaxAge
}

// EndID ends session id (DefaultSession ends the default session) and
// reports whether it was live.
func (s *Sessions) EndID(id string) bool {
	if id == DefaultSession {
		_, ok := s.Current()
		s.End()
		return ok
	}
	v, ok := s.byID.Load(id)
	if !ok {
		return false
	}
	return s.endID(id, v.(*idSession))
}

// endID removes e if it is still the session stored under id, and runs the
// end hook once.
func (s *Sessions) endID(id string, e *idSession) bool {
	if !s.byID.CompareAndDelete(id, e) {
		return false
	}
	if fn := s.onEnd.Load(); fn != nil {
		(*fn)(id)
	}
	return true
}

// ConsumeRecycled reports whether id was recently recycled (max-age exceeded)
// and removes it from the recycled set, so the next call sees session_not_found.
func (s *Sessions) ConsumeRecycled(id string) bool {
	_, loaded := s.recycled.LoadAndDelete(id)
	return loaded
}

// liveWithReason checks whether id is live. If the session was recycled (max
// age exceeded) the caller gets ReasonSessionRevalidationRequired; if it
// expired from idleness it gets ReasonSessionNotFound.
func (s *Sessions) liveWithReason(id string) (bool, string) {
	if s.ConsumeRecycled(id) {
		return false, ReasonSessionRevalidationRequired
	}
	live := s.Exists(id)
	if live {
		return true, ""
	}
	// Exists may have just recycled the session (max age detected during
	// live()); consume again to catch it.
	if s.ConsumeRecycled(id) {
		return false, ReasonSessionRevalidationRequired
	}
	return false, ReasonSessionNotFound
}

// Sweep ends every id session idle past the TTL and returns their ids.
func (s *Sessions) Sweep() []string {
	now := s.now()
	var ended []string
	s.byID.Range(func(k, v any) bool {
		if e := v.(*idSession); s.expired(e, now) && s.endID(k.(string), e) {
			ended = append(ended, k.(string))
		}
		return true
	})
	return ended
}

// Len is the number of live id sessions (not counting the default session).
func (s *Sessions) Len() int {
	n := 0
	s.byID.Range(func(_, _ any) bool { n++; return true })
	return n
}

// revokeIf revokes every session (default and id) whose subject matches: the
// identity is kept only so later calls deny subject_revoked until the
// session ends. It returns the revoked session ids (DefaultSession for the
// default session).
func (s *Sessions) revokeIf(match func(Subject) bool) []string {
	var revoked []string
	s.mu.Lock()
	if s.cur != nil && match(*s.cur) {
		s.cur = &Subject{UserID: s.cur.UserID, Status: StatusRevoked}
		revoked = append(revoked, DefaultSession)
	}
	s.mu.Unlock()
	s.byID.Range(func(k, v any) bool {
		e := v.(*idSession)
		e.mu.Lock()
		if match(e.sub) {
			e.sub = Subject{UserID: e.sub.UserID, Status: StatusRevoked}
			revoked = append(revoked, k.(string))
		}
		e.mu.Unlock()
		return true
	})
	return revoked
}

// revoke revokes every session.
func (s *Sessions) revoke() []string {
	return s.revokeIf(func(Subject) bool { return true })
}

// RevokeAll revokes every session (installation revoked) and returns their
// ids.
func (s *Sessions) RevokeAll() []string { return s.revoke() }
