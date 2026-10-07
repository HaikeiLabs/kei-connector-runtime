package policybundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/policybundlehealth"
)

type State string

const (
	Cold        State = "cold"
	Active      State = "active"
	Stale       State = "stale_but_valid"
	Expired     State = "expired"
	Invalid     State = "invalid"
	Unsupported State = "unsupported"
	Revoked     State = "revoked"
)

type diskState struct {
	Version        int64           `json:"highest_bundle_version"`
	PolicyRevision int64           `json:"policy_revision,omitempty"`
	Audience       Audience        `json:"audience"`
	Digest         string          `json:"bundle_digest,omitempty"`
	AcceptedAt     time.Time       `json:"accepted_at,omitempty"`
	ExpiresAt      time.Time       `json:"expires_at,omitempty"`
	ReasonCode     string          `json:"reason_code,omitempty"`
	LastCheck      time.Time       `json:"last_check,omitempty"`
	LastSuccess    time.Time       `json:"last_success,omitempty"`
	State          State           `json:"state"`
	Bundle         json.RawMessage `json:"-"`
}
type Store struct {
	dir, statePath, bundlePath string
	// mu orders this process's goroutines around the state file lock: flock
	// excludes other processes but is not synchronization in the Go memory
	// model, and the daemon checks the bundle from concurrent requests. It is
	// held only for the file read and check, never around a governed call.
	mu    sync.Mutex
	state diskState
}

func OpenStore(dir string) (*Store, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("runtime policy state directory is required")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create policy state directory: %w", err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return nil, errors.New("policy state path must be a real directory")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, fmt.Errorf("secure policy state directory: %w", err)
	}
	pdir := filepath.Join(dir, "policy")
	if err := os.MkdirAll(pdir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(pdir, 0700); err != nil {
		return nil, err
	}
	s := &Store{dir: pdir, statePath: filepath.Join(pdir, "state.json"), bundlePath: filepath.Join(pdir, "bundle.json"), state: diskState{State: Cold}}
	if err := s.withLock(func() error {
		if s.state.State == Invalid {
			return s.persist()
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return s, nil
}
func (s *Store) State() State { return s.state.State }

// HighestVersionFor returns the rollback watermark for one bundle audience.
// The watermark belongs to the installation that wrote it: state left by a
// different audience (a previous installation on this machine) does not bound
// the new installation's bundle versions.
func (s *Store) HighestVersionFor(installationID, orgID, workspaceID string) int64 {
	if s.heldByOtherAudience(Audience{InstallationID: installationID, OrgID: orgID, WorkspaceID: workspaceID}) {
		return 0
	}
	return s.state.Version
}

func (s *Store) heldByOtherAudience(want Audience) bool {
	return s.state.Version > 0 && s.state.Audience != want
}

func (s *Store) withLock(fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(filepath.Join(s.dir, "state.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open policy state lock: %w", err)
	}
	defer f.Close()
	if err := f.Chmod(0600); err != nil {
		return err
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("lock policy state: %w", err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	if err := s.reload(); err != nil {
		return err
	}
	return fn()
}
func readSecureBytes(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() || fi.Mode().Perm()&0077 != 0 {
		return nil, errors.New("policy state file permissions or type are unsafe")
	}
	return os.ReadFile(path)
}
func readSecureFile(path string, dst any) error {
	b, err := readSecureBytes(path)
	if err != nil {
		return err
	}
	return strictJSON(b, dst)
}
func (s *Store) reload() error {
	s.state = diskState{State: Cold}
	if err := readSecureFile(s.statePath, &s.state); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read policy state: %w", err)
	}
	bundle, err := readSecureBytes(s.bundlePath)
	if err == nil {
		s.state.Bundle = bundle
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read persisted policy bundle: %w", err)
	}
	if s.state.State != Cold && s.state.State != Revoked && (len(s.state.Bundle) == 0 || s.state.Digest == "") {
		s.state.State = Invalid
	}
	return nil
}

func (s *Store) Activate(bundle []byte, installationID, orgID, workspaceID string, now time.Time) (*Verified, error) {
	var verified *Verified
	err := s.withLock(func() error {
		highest := s.state.Version
		newInstallation := s.heldByOtherAudience(Audience{InstallationID: installationID, OrgID: orgID, WorkspaceID: workspaceID})
		if newInstallation {
			highest = 0
		}
		v, err := Validate(bundle, installationID, orgID, workspaceID, highest, now)
		if err != nil {
			s.state.LastCheck = now
			s.state.ReasonCode = healthReasonForError(err)
			if len(s.state.Bundle) == 0 {
				s.state.State = Invalid
				if errors.Is(err, ErrBundleUnsupported) {
					s.state.State = Unsupported
				}
			}
			_ = s.persist()
			return err
		}
		if newInstallation {
			if err := s.archive(now); err != nil {
				return fmt.Errorf("archive previous installation policy state: %w", err)
			}
			s.state = diskState{State: Cold}
		}
		s.state.Version = v.Payload.BundleVersion
		s.state.PolicyRevision = v.Payload.PolicyRevision
		s.state.Audience = v.Payload.Audience
		s.state.Digest = v.Digest
		s.state.AcceptedAt = now.UTC()
		s.state.ExpiresAt = v.Payload.NotAfter.UTC()
		s.state.ReasonCode = ""
		s.state.Bundle = append(json.RawMessage(nil), bundle...)
		s.state.LastCheck = now
		s.state.LastSuccess = now
		s.state.State = Active
		if err := s.persist(); err != nil {
			return err
		}
		verified = v
		return nil
	})
	return verified, err
}

// archive moves the previous installation's persisted state and bundle into
// policy/archive/<timestamp>-<installation>/. It never deletes them; the new
// installation then starts from a cold store with its own watermark.
func (s *Store) archive(now time.Time) error {
	label := s.state.Audience.InstallationID
	if !idPattern.MatchString(label) {
		label = "unknown-installation"
	}
	dst := filepath.Join(s.dir, "archive", now.UTC().Format("20060102T150405.000000000Z")+"-"+label)
	if err := os.MkdirAll(dst, 0700); err != nil {
		return err
	}
	for _, name := range []string{filepath.Base(s.statePath), filepath.Base(s.bundlePath)} {
		if err := os.Rename(filepath.Join(s.dir, name), filepath.Join(dst, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := syncDirectory(dst); err != nil {
		return err
	}
	return syncDirectory(s.dir)
}

func (s *Store) Check(installationID, orgID, workspaceID string, now time.Time) (*Verified, State, error) {
	var verified *Verified
	state := Cold
	err := s.withLock(func() error {
		if s.state.State == Revoked {
			state = Revoked
			return errors.New("installation revoked")
		}
		if s.state.State == Unsupported {
			state = Unsupported
			return ErrBundleUnsupported
		}
		if s.state.State == Invalid {
			state = Invalid
			return errors.New("policy bundle invalid")
		}
		if s.state.State == Expired {
			state = Expired
			return ErrBundleExpired
		}
		if len(s.state.Bundle) == 0 {
			state = Cold
			return errors.New("policy bundle missing")
		}
		v, e := Validate(s.state.Bundle, installationID, orgID, workspaceID, s.state.Version-1, now)
		if errors.Is(e, ErrBundleUnsupported) {
			s.state.State = Unsupported
			_ = s.persist()
			state = Unsupported
			return e
		}
		if errors.Is(e, ErrBundleExpired) {
			s.state.State = Expired
			_ = s.persist()
			state = Expired
			return ErrBundleExpired
		}
		if e != nil || v.Payload.BundleVersion != s.state.Version || v.Digest != s.state.Digest || s.state.LastSuccess.IsZero() {
			s.state.State = Invalid
			s.state.ReasonCode = healthReasonForError(e)
			_ = s.persist()
			state = Invalid
			return errors.New("persisted policy bundle invalid")
		}
		if now.Sub(s.state.LastSuccess) > time.Duration(v.Payload.Refresh.StaleAfterSeconds)*time.Second {
			s.state.State = Stale
		} else {
			s.state.State = Active
		}
		verified = v
		state = s.state.State
		return nil
	})
	return verified, state, err
}
func (s *Store) RefreshFailed(now time.Time) error {
	return s.withLock(func() error {
		s.state.LastCheck = now
		s.state.ReasonCode = string(policybundlehealth.ReasonRefreshFailed)
		return s.persist()
	})
}
func (s *Store) RecordRejectedCandidate(now time.Time, cause error) error {
	return s.withLock(func() error {
		s.state.LastCheck = now
		s.state.ReasonCode = healthReasonForError(cause)
		if len(s.state.Bundle) == 0 && s.state.State != Revoked {
			s.state.State = Invalid
			if errors.Is(cause, ErrBundleUnsupported) {
				s.state.State = Unsupported
			} else if errors.Is(cause, ErrBundleExpired) {
				s.state.State = Expired
			}
		}
		return s.persist()
	})
}
func (s *Store) RefreshSucceeded(now time.Time) error {
	return s.withLock(func() error {
		s.state.LastCheck = now
		s.state.LastSuccess = now
		s.state.ReasonCode = ""
		if s.state.State != Revoked && len(s.state.Bundle) > 0 {
			s.state.State = Active
		}
		return s.persist()
	})
}
func (s *Store) Revoke(now time.Time) error {
	return s.withLock(func() error {
		s.state.State = Revoked
		s.state.ReasonCode = string(policybundlehealth.ReasonRuntimeRevoked)
		s.state.Bundle = nil
		s.state.LastCheck = now
		return s.persist()
	})
}
func healthReasonForError(err error) string {
	switch {
	case errors.Is(err, ErrBundleUnsupported):
		return string(policybundlehealth.ReasonSchemaUnsupported)
	case errors.Is(err, ErrBundleExpired):
		return string(policybundlehealth.ReasonRefreshFailed)
	default:
		return string(policybundlehealth.ReasonIntegrityRejected)
	}
}

// HealthReport returns only the approved metadata snapshot. Audience and bundle
// bytes are read locally for validation but are never copied into the report.
func (s *Store) HealthReport(installationID, orgID, workspaceID string, now time.Time) (*policybundlehealth.Health, error) {
	_, state, _ := s.Check(installationID, orgID, workspaceID, now)
	var snapshot diskState
	if err := s.withLock(func() error { snapshot = s.state; return nil }); err != nil {
		return nil, err
	}
	if !snapshot.ExpiresAt.IsZero() && !now.Before(snapshot.ExpiresAt) && state != Revoked {
		state = Expired
	}
	h := &policybundlehealth.Health{SchemaVersion: 1, State: policybundlehealth.State(state)}
	if snapshot.LastCheck.IsZero() {
		h.CheckedAt = nil
	} else {
		checked := snapshot.LastCheck.UTC()
		h.CheckedAt = &checked
	}
	if snapshot.Version > 0 && snapshot.PolicyRevision > 0 && snapshot.Digest != "" && !snapshot.AcceptedAt.IsZero() && !snapshot.ExpiresAt.IsZero() {
		version, revision, digest := snapshot.Version, snapshot.PolicyRevision, snapshot.Digest
		accepted, expires := snapshot.AcceptedAt.UTC(), snapshot.ExpiresAt.UTC()
		h.BundleVersion, h.PolicyRevision, h.BundleDigest = &version, &revision, &digest
		h.AcceptedAt, h.ExpiresAt = &accepted, &expires
	}
	var reason *policybundlehealth.Reason
	switch state {
	case Cold:
		if h.CheckedAt != nil {
			reason = reasonPtr(policybundlehealth.ReasonBundleMissing)
		}
	case Active:
	case Stale:
		reason = reasonPtr(policybundlehealth.ReasonBundleStale)
	case Expired:
		reason = reasonPtr(policybundlehealth.ReasonBundleExpired)
	case Unsupported:
		reason = reasonPtr(policybundlehealth.ReasonSchemaUnsupported)
	case Revoked:
		reason = reasonPtr(policybundlehealth.ReasonRuntimeRevoked)
	case Invalid:
		code := snapshot.ReasonCode
		if code == "" {
			code = string(policybundlehealth.ReasonRefreshFailed)
		}
		parsed := policybundlehealth.Reason(code)
		reason = &parsed
	}
	h.ReasonCode = reason
	if err := h.Validate(false); err != nil {
		return nil, err
	}
	return h, nil
}

func reasonPtr(reason policybundlehealth.Reason) *policybundlehealth.Reason { return &reason }

func (s *Store) persist() error {
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(s.dir, 0700); err != nil {
		return err
	}
	if len(s.state.Bundle) > 0 {
		if err := writeAtomicBytes(s.bundlePath, s.state.Bundle); err != nil {
			return err
		}
	} else if s.state.State == Revoked || s.state.State == Invalid || s.state.State == Unsupported {
		if err := os.Remove(s.bundlePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := writeAtomic(s.statePath, s.state); err != nil {
		return err
	}
	return syncDirectory(s.dir)
}
func writeAtomic(path string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeAtomicBytes(path, b)
}
func writeAtomicBytes(path string, b []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".policy-state-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
func syncDirectory(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
