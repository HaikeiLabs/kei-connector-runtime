// Package runtime contains customer-runtime control-plane operations.
package runtime

import "errors"

// ErrInstallationRevoked is returned when the runtime installation has been
// revoked or is inactive. Callers should clear local policy state.
var ErrInstallationRevoked = errors.New("runtime installation is revoked or inactive")

// PolicyConfig is the subset of the root Config that the runtime policy
// package needs, abstracted so runtime/ never imports the root package.
type PolicyConfig interface {
	PolicyStateDir() string
	Token() string
	ControlPlaneURL() string
	IsProduction() bool
	Validate() error
	IsRuntime() bool
	PolicyAuditPath() string
	PolicyAuditMaxBytes() int64
}

// Identity is the subset of RuntimeIdentity needed for policy operations.
type Identity struct {
	ID          string
	OrgID       string
	WorkspaceID *string
}

// IdentityFunc is a function that resolves the runtime identity.
type IdentityFunc func() (*Identity, error)

// SyncBundleFunc is a function that fetches and persists the policy bundle
// for the given identity. The caller supplies the closure from the root
// package where syncPolicyBundle and Config live.
type SyncBundleFunc func(identity *Identity) error
