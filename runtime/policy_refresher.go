package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/harnessresync"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

const (
	defaultPolicyPollInterval = 60 * time.Second
	minPolicyPollInterval     = 30 * time.Second
	maxPolicyPollInterval     = 300 * time.Second
	// failureLogInterval suppresses repeated failure logs: at most one log
	// per N polls while the store state does not change.
	failureLogInterval = 10
)

// PolicyRefresher keeps the persisted bundle current inside `kei-proxy serve`
// (ADR-026 §5): it polls on the bundle's advised interval, clamped to
// [30 s, 300 s] with ±10 % jitter, and holds the state directory's refresher
// lock so only one process refreshes. A failed refresh never replaces the
// active bundle; it ages into stale_but_valid and then expires on time.
type PolicyRefresher struct {
	cfg     PolicyConfig
	timeout time.Duration
	whoami  IdentityFunc
	sync    SyncBundleFunc
	// OnIdentity runs when identity is first resolved (from whoami or
	// seeded from the persisted bundle state at startup).
	OnIdentity func(*Identity)
	// AfterSync runs after every sync attempt with its result.
	AfterSync func(error)
	// OnBootstrap runs once with the result of the first policy sync attempt.
	OnBootstrap   func(error)
	bootstrapDone bool
	// After is the timer factory for poll intervals. Exported for testing.
	After func(time.Duration) <-chan time.Time
	// Jitter is the jitter function applied to each poll interval. Exported for testing.
	Jitter func(time.Duration) time.Duration
	// CheckRevocation tests whether an identity error is a revocation.
	CheckRevocation func(error) bool
	// RevokeState clears the local policy state on revocation.
	RevokeState func()
	// HarnessResync, when set, runs beside the loop while it holds the
	// refresher lock and is told about each successful refresh (HAI-432).
	HarnessResync *harnessresync.Resyncer
	// lastFailureState is the store state the last failure was logged at;
	// used to detect state transitions for rate-limited logging.
	lastFailureState policybundle.State
	// failureLogTick counts consecutive failure polls; reset on success.
	failureLogTick int
	// stateDirClaimed means the caller already holds the refresher lock
	// through ClaimStateDir, so Run must not take it again.
	stateDirClaimed bool
}

// NewPolicyRefresher creates a PolicyRefresher bound to the given config
// and identity/sync closures.
func NewPolicyRefresher(cfg PolicyConfig, whoami IdentityFunc, sync SyncBundleFunc, checkRevocation func(error) bool, revokeState func()) *PolicyRefresher {
	timeout := 10 * time.Second
	return &PolicyRefresher{
		cfg:             cfg,
		timeout:         timeout,
		whoami:          whoami,
		sync:            sync,
		CheckRevocation: checkRevocation,
		RevokeState:     revokeState,
		After:           time.After,
		Jitter:          PolicyJitter,
	}
}

// Run starts the refresh loop. It blocks until ctx is cancelled.
func (r *PolicyRefresher) Run(ctx context.Context) {
	store, err := policybundle.OpenStore(r.cfg.PolicyStateDir())
	if err != nil {
		slog.Error("policy refresher cannot open state directory; runtime stays deny-only", "error", err)
		return
	}
	if !r.stateDirClaimed {
		release, err := store.LockRefresher()
		if errors.Is(err, policybundle.ErrRefresherLocked) {
			slog.Info("policy refresher already running for this state directory")
			return
		}
		if err != nil {
			slog.Error("policy refresher lock failed; runtime stays deny-only", "error", err)
			return
		}
		defer release()
	}
	if r.HarnessResync != nil {
		resyncCtx, stopResync := context.WithCancel(ctx)
		resyncDone := make(chan struct{})
		go func() {
			defer close(resyncDone)
			r.HarnessResync.Run(resyncCtx)
		}()
		defer func() {
			stopResync()
			<-resyncDone
		}()
	}

	// Seed identity from the persisted bundle state so the evaluator is
	// available even when the control plane is unreachable at startup.
	// whoami becomes a REFRESH rather than a gate (HAI-700).
	identity := seedIdentityFromStore(store, time.Now().UTC())
	if identity != nil && r.OnIdentity != nil {
		r.OnIdentity(identity)
	}

	for {
		// Always try whoami as a refresh, but tolerate failure when we
		// already have a fallback identity seeded from the persisted state.
		refreshed, err := r.whoami()
		switch {
		case err == nil && refreshed != nil:
			identity = refreshed
			if r.OnIdentity != nil {
				r.OnIdentity(identity)
			}
		case r.CheckRevocation != nil && r.CheckRevocation(err):
			r.RevokeState()
			r.notify(ErrInstallationRevoked)
			identity = nil
		case ctx.Err() == nil && identity == nil:
			slog.Warn("policy refresher identity unavailable; runtime stays deny-only until it resolves", "error", err)
		}
		if identity != nil {
			beforeState := store.State()
			err := r.sync(identity)
			if !r.bootstrapDone {
				r.bootstrapDone = true
				if r.OnBootstrap != nil {
					r.OnBootstrap(err)
				}
			}
			afterState := store.State()
			if err != nil && ctx.Err() == nil {
				r.logSyncFailure(err, beforeState, afterState)
			} else if err == nil {
				// Sync succeeded or returned nil (409). Check if the store
				// state indicates a failure (e.g. 409 on cold start).
				r.failureLogTick = 0
				r.lastFailureState = ""
				if r.HarnessResync != nil {
					r.HarnessResync.BundleRefreshed(bundleKey(store))
				}
			}
			r.notify(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-r.After(r.Jitter(PollInterval(store, identity))):
		}
	}
}

// seedIdentityFromStore tries to build an Identity from the persisted policy
// state file. It returns nil when no audience is available (cold start,
// revoked store, or corrupt state), which means the loop falls through to
// the normal whoami-as-gate path.
//
// now is the reference time for status checks (expiry, staleness). Tests
// should pass a synthetic time to verify expired-bundle behaviour.
func seedIdentityFromStore(store *policybundle.Store, now time.Time) *Identity {
	status, err := store.Status(now)
	if err != nil {
		return nil
	}
	if status.Audience == nil || status.Audience.InstallationID == "" || status.Audience.OrgID == "" || status.Audience.WorkspaceID == "" {
		return nil
	}
	// Do not seed from a store that has been explicitly revoked — the
	// loop must first re-resolve identity via whoami before allowing
	// any policy decisions.
	if status.State == policybundle.Revoked {
		return nil
	}
	return &Identity{
		ID:          status.Audience.InstallationID,
		OrgID:       status.Audience.OrgID,
		WorkspaceID: &status.Audience.WorkspaceID,
		// AgentID is unknown without whoami; it is not needed for
		// evaluator construction or for policy decisions.
	}
}

// logSyncFailure logs a policy sync failure with rate-limiting and structured
// attributes. It fires unconditionally on a state transition and at most every
// failureLogInterval polls while the state remains the same.
func (r *PolicyRefresher) logSyncFailure(err error, before, after policybundle.State) {
	r.failureLogTick++

	stateChanged := before != after
	shouldLog := stateChanged || r.failureLogTick == 1 || r.failureLogTick%failureLogInterval == 0
	if !shouldLog {
		return
	}

	attrs := []any{"error", err}
	var bre *bundleRefreshError
	if errors.As(err, &bre) {
		attrs = append(attrs, bre.logFields()...)
	}
	if stateChanged {
		attrs = append(attrs, "state_transition", string(before)+"->"+string(after))
	}
	slog.Warn("policy bundle refresh failed; the active bundle stays until it expires", attrs...)

	r.lastFailureState = after
}

// bundleKey identifies the active bundle, so a resync check runs only when
// the refresh changed it.
func bundleKey(store *policybundle.Store) string {
	status, err := store.Status(time.Now().UTC())
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s/%d/%s", status.BundleID, status.BundleVersion, status.BundleDigest)
}

func (r *PolicyRefresher) notify(err error) {
	if r.AfterSync != nil {
		r.AfterSync(err)
	}
}

// PollInterval is the active bundle's advised interval, clamped, or the
// default when no bundle is active.
func PollInterval(store *policybundle.Store, identity *Identity) time.Duration {
	if identity == nil || identity.WorkspaceID == nil {
		return defaultPolicyPollInterval
	}
	status, err := store.Status(time.Now().UTC())
	if err != nil || status.PollIntervalSeconds == 0 {
		return defaultPolicyPollInterval
	}
	return ClampPollInterval(time.Duration(status.PollIntervalSeconds) * time.Second)
}

// ClampPollInterval clamps d to [minPolicyPollInterval, maxPolicyPollInterval].
func ClampPollInterval(d time.Duration) time.Duration {
	return min(max(d, minPolicyPollInterval), maxPolicyPollInterval)
}

// PolicyJitter spreads d by ±10 %.
func PolicyJitter(d time.Duration) time.Duration {
	spread := int64(d) / 10
	return d - time.Duration(spread) + time.Duration(rand.Int64N(2*spread+1))
}

// StartPolicyRefresher starts the policy-bundle refresh loop in a background
// goroutine. It is a no-op when IsRuntime() is false. The returned stop
// function blocks until the refresher has shut down.
//
// This follows the same pattern as StartCollector so callers (serve.go and
// runtime.go) have a uniform way to start background runtime loops.
func StartPolicyRefresher(
	ctx context.Context,
	cfg PolicyConfig,
	whoami IdentityFunc,
	sync SyncBundleFunc,
	checkRevocation func(error) bool,
	revokeState func(),
	onIdentity func(*Identity),
	afterSync func(error),
	opts ...RefresherOption,
) (stop func()) {
	if !cfg.IsRuntime() {
		return func() {}
	}
	refresher := NewPolicyRefresher(cfg, whoami, sync, checkRevocation, revokeState)
	refresher.OnIdentity = onIdentity
	refresher.AfterSync = afterSync
	for _, opt := range opts {
		opt(refresher)
	}

	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		refresher.Run(ctx)
	}()
	return func() {
		cancel()
		<-done
	}
}

// RefresherOption configures a PolicyRefresher started by
// StartPolicyRefresher.
type RefresherOption func(*PolicyRefresher)

// WithBootstrapResult registers a callback for the first policy sync result.
func WithBootstrapResult(callback func(error)) RefresherOption {
	return func(p *PolicyRefresher) { p.OnBootstrap = callback }
}

// WithHarnessResync runs r beside the refresher (nil is a no-op).
func WithHarnessResync(r *harnessresync.Resyncer) RefresherOption {
	return func(p *PolicyRefresher) { p.HarnessResync = r }
}

// WithClaimedStateDir tells the refresher that its caller already holds the
// state directory through ClaimStateDir.
func WithClaimedStateDir() RefresherOption {
	return func(p *PolicyRefresher) { p.stateDirClaimed = true }
}
