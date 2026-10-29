package policybundle

import (
	bundle "github.com/HaikeiLabs/kei-connector-contracts/bundle"
	"time"
)

// DecisionPermit is the ADR-028 permit decision word, for callers that report
// a decision in that vocabulary.
const DecisionPermit = bundle.DecisionPermit

// Session subject statuses (ADR-026 G0, kei#681). The subject is established
// for a worker session by machine login plus kei or harness login and is held
// only in kei-proxy memory; it is never read from a per-call request.
const (
	SubjectLinked         = bundle.SubjectLinked
	SubjectUnlinked       = bundle.SubjectUnlinked
	SubjectPending        = "pending"
	SubjectRevoked        = "revoked"
	SubjectCrossWorkspace = "cross_workspace"
)

// SessionSubject is the acting user of the current worker session. It
// carries no groups: the groups a decision uses are the ones the verified
// bundle holds for that user (B-20), never the ones a session claims.
type SessionSubject = bundle.SessionSubject

// Memberships answers which groups, org roles and workspace grant the bundle
// holds for a user. Only a kei.policy-bundle/v2 bundle carries them; any other
// bundle yields no Memberships and every membership-dependent source fails
// closed.
type Memberships = bundle.Memberships

// BundleMemberships returns the memberships carried by the bundle, or nil
// when the bundle does not carry them (mode=online or no identities).
func BundleMemberships(v *Verified) Memberships {
	return BundleMembershipsAt(v, time.Now())
}

// BundleMembershipsAt binds identity expiry checks to the evaluator's clock so
// snapshot freshness and expiry can be tested deterministically.
func BundleMembershipsAt(v *Verified, now time.Time) Memberships {
	if v == nil || v.Payload.Schema != "kei.policy-bundle/v2" || v.Payload.SubjectResolution.Mode != "bundle" || len(v.Payload.Identities) == 0 || !v.SubjectSnapshotFresh(now) {
		return nil
	}
	return &bundleMemberships{identities: v.Payload.Identities, now: now}
}

type bundleMemberships struct {
	identities []Identity
	now        time.Time
}

// Lookup aggregates every unexpired identity row the bundle holds for userID:
// the user is granted when any row is linked, and the groups and org roles are
// the union across rows.
func (m *bundleMemberships) Lookup(userID string) (groups, roles []string, granted, known bool) {
	groupSet, roleSet := map[string]bool{}, map[string]bool{}
	for _, id := range m.identities {
		if id.UserID != userID || (!id.ExpireTime.IsZero() && !m.now.Before(id.ExpireTime)) {
			continue
		}
		known = true
		granted = granted || id.Status == SubjectLinked
		for _, group := range id.Groups {
			groupSet[group] = true
		}
		for _, role := range id.OrgRoles {
			roleSet[role] = true
		}
	}
	for group := range groupSet {
		groups = append(groups, group)
	}
	for role := range roleSet {
		roles = append(roles, role)
	}
	return groups, roles, granted, known
}

// LookupLinkedUser resolves a CLI session's user_id against bundle identities.
// Remote sessions must use the exact source/external_id key instead.
func (v *Verified) LookupLinkedUser(userID string, now time.Time) (Identity, bool) {
	return v.toBundle().LookupLinkedUser(userID, now)
}

func statusReasonCode(status string) string {
	switch status {
	case SubjectPending:
		return "subject_pending"
	case SubjectRevoked:
		return "subject_revoked"
	case SubjectCrossWorkspace:
		return "subject_cross_workspace"
	default:
		return "subject_unlinked"
	}
}

// SubjectSnapshotFresh reports whether the bundle subject snapshot is usable.
// HAI-452: the snapshot is trusted for the session lifetime — no
// max_cache_seconds window is enforced. Returns true when the bundle
// itself has been issued (IssuedAt ≤ now, allowing MaxIssuedAtClockSkew so a
// bundle Validate accepted is usable at once).
func (v *Verified) SubjectSnapshotFresh(now time.Time) bool {
	return v.toBundle().SubjectSnapshotFresh(now)
}

// LookupIdentity resolves an external session key against the verified
// bundle's ADR-034 identities table. Duplicate matches and expired entries are
// rejected rather than allowing array order to select an identity.
func (v *Verified) LookupIdentity(source, externalID string, now time.Time) (Identity, bool) {
	return v.toBundle().LookupIdentity(source, externalID, now)
}

// EvaluateSession decides a call with the in-memory session subject and no
// catalog round trip. Registry and agent checks come first, then the subject
// gate (a non-linked session denies before any policy), then the
// catalog-ordered policy walk. A human-source policy whose dst matches never
// falls through: without a session it denies subject_unlinked, and without
// bundle memberships a group or org source denies subject_pending.
func (v *Verified) EvaluateSession(call Call, subject *SessionSubject, members Memberships) Decision {
	return v.EvaluateSessionAt(call, subject, members, time.Now())
}

// EvaluateSessionAt decides a call for a v2 bundle: a stale subject snapshot
// denies, and every connector operation otherwise needs complete-plan
// preflight. A bundle that is not kei.policy-bundle/v2 is denied unsupported.
func (v *Verified) EvaluateSessionAt(call Call, subject *SessionSubject, members Memberships, now time.Time) Decision {
	if v.Payload.Schema != "kei.policy-bundle/v2" {
		return Decision{Outcome: "deny", ReasonCode: "policy_bundle_unsupported", Reason: "only a kei.policy-bundle/v2 bundle can decide; upgrade the catalog to deliver one"}
	}
	if !v.SubjectSnapshotFresh(now) {
		return Decision{Outcome: "deny", ReasonCode: "subject_snapshot_stale", Reason: "the local subject snapshot is missing or stale"}
	}
	return Decision{Outcome: "deny", ReasonCode: "preflight_required", Reason: "v2 connector operations require complete-plan preflight"}
}

func subjectGate(s *SessionSubject) (Decision, bool) {
	switch s.Status {
	case SubjectLinked:
		if s.UserID != "" {
			return Decision{}, false
		}
		return Decision{Outcome: "deny", ReasonCode: "subject_unlinked", Reason: "the session subject has no user id"}, true
	case SubjectPending:
		return Decision{Outcome: "deny", ReasonCode: "subject_pending", Reason: "the session subject's workspace access is pending"}, true
	case SubjectRevoked:
		return Decision{Outcome: "deny", ReasonCode: "subject_revoked", Reason: "the session subject was revoked"}, true
	case SubjectCrossWorkspace:
		return Decision{Outcome: "deny", ReasonCode: "subject_cross_workspace", Reason: "the session subject belongs to another workspace"}, true
	default:
		return Decision{Outcome: "deny", ReasonCode: "subject_unlinked", Reason: "the session subject is not linked"}, true
	}
}
