package pdp

import (
	"encoding/json"
	"errors"
	"sync"

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
	Status     Status
	Enrollment json.RawMessage
	Token      string
}

// Sessions holds the current worker session's subject and optional credential
// in memory only. It is never persisted and ends with End, a revocation, or
// the process. The credential is set by the serve daemon on a linked CLI
// session when KEI_CREDENTIAL_RELEASE=identity.
type Sessions struct {
	mu         sync.RWMutex
	cur        *Subject
	credential string
}

func NewSessions() *Sessions { return &Sessions{} }

// Start begins a session, replacing any previous one.
func (s *Sessions) Start(sub Subject) error {
	switch sub.Status {
	case StatusLinked:
		if sub.UserID == "" {
			return errors.New("pdp: a linked session subject requires a user id")
		}
	case StatusUnlinked, StatusPending, StatusCrossWorkspace, StatusRevoked:
	default:
		return errors.New("pdp: session status must be linked, unlinked, pending, cross_workspace or revoked")
	}
	if sub.Status != StatusUnlinked {
		sub.Enrollment = nil
	}
	sub.Enrollment = append(json.RawMessage(nil), sub.Enrollment...)
	s.mu.Lock()
	s.cur = &sub
	s.credential = ""
	s.mu.Unlock()
	return nil
}

// SetCredential stores the session credential in memory.
func (s *Sessions) SetCredential(cred string) {
	s.mu.Lock()
	s.credential = cred
	s.mu.Unlock()
}

// Credential returns a copy of the stored credential and true, or false if
// none is set.
func (s *Sessions) Credential() (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.credential, s.credential != ""
}

// ClearCredential removes the stored credential.
func (s *Sessions) ClearCredential() {
	s.mu.Lock()
	s.credential = ""
	s.mu.Unlock()
}

// End ends the session; later calls have no session subject. The stored
// credential is cleared.
func (s *Sessions) End() {
	s.mu.Lock()
	s.cur = nil
	s.credential = ""
	s.mu.Unlock()
}

// Current returns a copy of the session subject.
func (s *Sessions) Current() (Subject, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cur == nil {
		return Subject{}, false
	}
	sub := *s.cur
	sub.Enrollment = append(json.RawMessage(nil), s.cur.Enrollment...)
	return sub, true
}

// revoke ends the session by revocation: the identity is kept only so later
// calls deny subject_revoked until a new session starts.
func (s *Sessions) revoke() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur != nil {
		s.cur = &Subject{UserID: s.cur.UserID, Status: StatusRevoked}
	}
}
