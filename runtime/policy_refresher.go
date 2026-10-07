package runtime

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

const (
	defaultPolicyPollInterval = 60 * time.Second
	minPolicyPollInterval     = 30 * time.Second
	maxPolicyPollInterval     = 300 * time.Second
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
	// OnIdentity runs once, when whoami first succeeds.
	OnIdentity func(*Identity)
	// AfterSync runs after every sync attempt with its result.
	AfterSync func(error)
	// After is the timer factory for poll intervals. Exported for testing.
	After func(time.Duration) <-chan time.Time
	// Jitter is the jitter function applied to each poll interval. Exported for testing.
	Jitter func(time.Duration) time.Duration
	// CheckRevocation tests whether an identity error is a revocation.
	CheckRevocation func(error) bool
	// RevokeState clears the local policy state on revocation.
	RevokeState func()
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

	var identity *Identity
	for {
		if identity == nil {
			id, err := r.whoami()
			switch {
			case err == nil && id != nil:
				identity = id
				if r.OnIdentity != nil {
					r.OnIdentity(identity)
				}
			case r.CheckRevocation != nil && r.CheckRevocation(err):
				r.RevokeState()
				r.notify(ErrInstallationRevoked)
			case ctx.Err() == nil:
				slog.Warn("policy refresher identity unavailable; runtime stays deny-only until it resolves", "error", err)
			}
		}
		if identity != nil {
			err := r.sync(identity)
			if err != nil && ctx.Err() == nil {
				slog.Warn("policy bundle refresh failed; the active bundle stays until it expires", "error", err)
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
) (stop func()) {
	if !cfg.IsRuntime() {
		return func() {}
	}
	refresher := NewPolicyRefresher(cfg, whoami, sync, checkRevocation, revokeState)
	refresher.OnIdentity = onIdentity
	refresher.AfterSync = afterSync

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
