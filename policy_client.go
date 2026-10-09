package connectorruntime

import (
	"context"
	"errors"
	"net/http"
	"time"

	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

var (
	ErrPolicyInstallationRevoked = keiruntime.ErrPolicyInstallationRevoked
	ErrPolicyAuthorizationDenied = keiruntime.ErrPolicyAuthorizationDenied
	ErrPolicyBundleNotReady      = keiruntime.ErrPolicyBundleNotReady
)

func SyncPolicyBundle(ctx context.Context, cfg Config, identity *RuntimeIdentity, timeout time.Duration) error {
	return keiruntime.SyncPolicyBundle(ctx, cfg, identityFromRoot(identity), timeout)
}

func RevokePolicyState(cfg Config) {
	keiruntime.RevokePolicyState(cfg)
}

func IsRuntimeRevocation(err error) bool {
	var who *WhoamiFailure
	if errors.As(err, &who) && who.Category == WhoamiFailureHTTPStatus && (who.StatusCode == http.StatusUnauthorized || who.StatusCode == http.StatusForbidden) {
		return true
	}
	var beat *HeartbeatFailure
	return errors.As(err, &beat) && beat.Outcome == HeartbeatUnauthorized
}

func identityFromRoot(id *RuntimeIdentity) *keiruntime.Identity {
	if id == nil {
		return nil
	}
	return &keiruntime.Identity{
		ID:          id.ID,
		OrgID:       id.OrgID,
		WorkspaceID: id.WorkspaceID,
	}
}
