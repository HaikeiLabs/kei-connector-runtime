package policybundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Status is what `kei-proxy policy show` reports: metadata of the persisted
// bundle and the state it would be enforced in now. It never carries
// policies, subjects or credentials.
type Status struct {
	State               State     `json:"state"`
	Audience            *Audience `json:"audience,omitempty"`
	BundleID            string    `json:"bundle_id,omitempty"`
	BundleVersion       int64     `json:"bundle_version,omitempty"`
	BundleDigest        string    `json:"bundle_digest,omitempty"`
	PolicyRevision      int64     `json:"policy_revision,omitempty"`
	IssuedAt            time.Time `json:"issued_at,omitzero"`
	NotAfter            time.Time `json:"not_after,omitzero"`
	PollIntervalSeconds int       `json:"poll_interval_seconds,omitempty"`
	StaleAfterSeconds   int       `json:"stale_after_seconds,omitempty"`
	LastCheck           time.Time `json:"last_check,omitzero"`
	LastSuccess         time.Time `json:"last_success,omitzero"`
	PolicyCount         int       `json:"policy_count"`
	ToolCount           int       `json:"tool_count"`
	Error               string    `json:"error,omitempty"`
}

// Status reports the persisted state without changing it. The bundle is
// re-validated against the persisted audience; the state is the one Check
// would enforce at now.
func (s *Store) Status(now time.Time) (Status, error) {
	var st Status
	err := s.withLock(func() error {
		st = Status{State: s.state.State, LastCheck: s.state.LastCheck, LastSuccess: s.state.LastSuccess}
		if s.state.Audience != (Audience{}) {
			aud := s.state.Audience
			st.Audience = &aud
		}
		if len(s.state.Bundle) == 0 || s.state.State == Revoked || s.state.State == Invalid || s.state.State == Unsupported {
			return nil
		}
		aud := s.state.Audience
		v, err := Validate(s.state.Bundle, aud.InstallationID, aud.OrgID, aud.WorkspaceID, s.state.Version-1, now)
		switch {
		case errors.Is(err, ErrBundleExpired):
			st.State = Expired
		case errors.Is(err, ErrBundleUnsupported):
			st.State = Unsupported
		case err != nil || v.Payload.BundleVersion != s.state.Version || v.Digest != s.state.Digest:
			st.State = Invalid
		}
		if err != nil {
			st.Error = err.Error()
			if v == nil {
				return nil
			}
		}
		if st.State == Active || st.State == Stale {
			st.State = Active
			if now.Sub(s.state.LastSuccess) > time.Duration(v.Payload.Refresh.StaleAfterSeconds)*time.Second {
				st.State = Stale
			}
		}
		p := v.Payload
		st.BundleID, st.BundleVersion, st.BundleDigest, st.PolicyRevision = p.BundleID, p.BundleVersion, v.Digest, p.PolicyRevision
		st.IssuedAt, st.NotAfter = p.IssuedAt, p.NotAfter
		st.PollIntervalSeconds, st.StaleAfterSeconds = p.Refresh.PollIntervalSeconds, p.Refresh.StaleAfterSeconds
		var counts struct {
			Policies []json.RawMessage `json:"policies"`
			Tools    []json.RawMessage `json:"tools"`
		}
		if json.Unmarshal(p.PolicySet, &counts) == nil {
			st.PolicyCount, st.ToolCount = len(counts.Policies), len(counts.Tools)
		}
		return nil
	})
	return st, err
}

// ErrRefresherLocked means another process already refreshes this state
// directory (ADR-026 §5: one refresher per state directory).
var ErrRefresherLocked = errors.New("another process holds the policy refresher lock")

// LockRefresher takes the state directory's exclusive refresher lock without
// waiting. The caller holds it for as long as it refreshes.
func (s *Store) LockRefresher() (release func(), err error) {
	f, err := os.OpenFile(filepath.Join(s.dir, "refresher.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open policy refresher lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrRefresherLocked
		}
		return nil, fmt.Errorf("lock policy refresher: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
