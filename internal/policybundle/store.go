package policybundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
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
	Version     int64           `json:"highest_bundle_version"`
	Audience    Audience        `json:"audience"`
	Digest      string          `json:"bundle_digest,omitempty"`
	LastCheck   time.Time       `json:"last_check,omitempty"`
	LastSuccess time.Time       `json:"last_success,omitempty"`
	State       State           `json:"state"`
	Bundle      json.RawMessage `json:"-"`
}
type Store struct {
	dir, statePath, bundlePath string
	state                      diskState
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
func (s *Store) State() State          { return s.state.State }
func (s *Store) HighestVersion() int64 { return s.state.Version }

func (s *Store) withLock(fn func() error) error {
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
		v, err := Validate(bundle, installationID, orgID, workspaceID, s.state.Version, now)
		if err != nil {
			s.state.LastCheck = now
			if len(s.state.Bundle) == 0 {
				s.state.State = Invalid
				if errors.Is(err, ErrBundleUnsupported) {
					s.state.State = Unsupported
				}
			}
			_ = s.persist()
			return err
		}
		s.state.Version = v.Payload.BundleVersion
		s.state.Audience = v.Payload.Audience
		s.state.Digest = v.Digest
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
	return s.withLock(func() error { s.state.LastCheck = now; return s.persist() })
}
func (s *Store) RecordRejectedCandidate(now time.Time, cause error) error {
	return s.withLock(func() error {
		s.state.LastCheck = now
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
		if s.state.State != Revoked && len(s.state.Bundle) > 0 {
			s.state.State = Active
		}
		return s.persist()
	})
}
func (s *Store) Revoke(now time.Time) error {
	return s.withLock(func() error {
		s.state.State = Revoked
		s.state.Bundle = nil
		s.state.Digest = ""
		s.state.LastCheck = now
		return s.persist()
	})
}
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
