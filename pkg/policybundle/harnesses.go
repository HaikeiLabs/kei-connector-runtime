package policybundle

import (
	"errors"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/bundle"
)

// Harnesses returns the registered harnesses from the persisted bundle when
// the bundle is present and currently valid (active or stale). Every other
// state — missing, unreadable, invalid, unsupported, revoked, or expired —
// yields an empty slice and a nil error, so callers treat them uniformly as
// "no harness registered". The bundle is re-validated against the persisted
// audience at now, matching the state Check would enforce, so a bundle whose
// not_after has passed reports empty even when the persisted state still says
// active. Harnesses live at the top level of both the v1 and v2 payloads.
func (s *Store) Harnesses(now time.Time) ([]Harness, error) {
	var harnesses []Harness
	err := s.withLock(func() error {
		if len(s.state.Bundle) == 0 || (s.state.State != Active && s.state.State != Stale) {
			return nil
		}
		aud := s.state.Audience
		v, err := Validate(s.state.Bundle, aud.InstallationID, aud.OrgID, aud.WorkspaceID, s.state.Version-1, now)
		switch {
		case errors.Is(err, ErrBundleExpired):
			return nil
		case errors.Is(err, ErrBundleUnsupported):
			return nil
		case err != nil || v.Payload.BundleVersion != s.state.Version || v.Digest != s.state.Digest:
			return nil
		}
		harnesses = v.Payload.Harnesses
		return nil
	})
	return harnesses, err
}

// HarnessKinds returns the harness kind registry of the persisted bundle in
// force, or nil when there is no such bundle or it carries no registry. It
// follows the same rules as Harnesses: a missing, invalid, unsupported or
// expired bundle reports empty.
func (s *Store) HarnessKinds(now time.Time) ([]bundle.HarnessKind, error) {
	var kinds []bundle.HarnessKind
	err := s.withLock(func() error {
		if len(s.state.Bundle) == 0 || (s.state.State != Active && s.state.State != Stale) {
			return nil
		}
		aud := s.state.Audience
		v, err := Validate(s.state.Bundle, aud.InstallationID, aud.OrgID, aud.WorkspaceID, s.state.Version-1, now)
		switch {
		case errors.Is(err, ErrBundleExpired), errors.Is(err, ErrBundleUnsupported):
			return nil
		case err != nil || v.Payload.BundleVersion != s.state.Version || v.Digest != s.state.Digest:
			return nil
		}
		kinds = v.Payload.HarnessKinds
		return nil
	})
	return kinds, err
}
