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
// subject_unlinked denial.
type Subject struct {
	UserID     string
	Email      string
	Status     Status
	Enrollment json.RawMessage
}

// Sessions holds the current worker session's subject in memory only. It is
// never persisted and ends with End, a revocation, or the process.
type Sessions struct {
	mu  sync.RWMutex
	cur *Subject
}

func NewSessions() *Sessions { return &Sessions{} }

// Start begins a session, replacing any previous one.
func (s *Sessions) Start(sub Subject) error {
	switch sub.Status {
	case StatusLinked:
		if sub.UserID == "" {
			return errors.New("pdp: a linked session subject requires a user id")
		}
	case StatusUnlinked, StatusPending, StatusCrossWorkspace:
	default:
		return errors.New("pdp: session status must be linked, unlinked, pending or cross_workspace")
	}
	if sub.Status != StatusUnlinked {
		sub.Enrollment = nil
	}
	sub.Enrollment = append(json.RawMessage(nil), sub.Enrollment...)
	s.mu.Lock()
	s.cur = &sub
	s.mu.Unlock()
	return nil
}

// End ends the session; later calls have no session subject.
func (s *Sessions) End() {
	s.mu.Lock()
	s.cur = nil
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
