package harnessresync

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"time"
)

const (
	// DefaultInterval is the timer between drift checks.
	DefaultInterval = 5 * time.Minute
	// MaxInterval caps the backoff.
	MaxInterval = time.Hour
	// backoffWindow is how many cycles a harness must stay clean before a
	// new rewrite stops counting as a repeat.
	backoffWindow = 3
)

// Resyncer checks desktop harness config for drift after each bundle change
// and on a timer, and resyncs it when it drifted. A harness that another
// writer rewrites again within three cycles doubles the timer, up to
// MaxInterval; three clean cycles reset it.
//
// Every failure is logged and ignored: the resyncer never touches bundle
// refresh or heartbeats, and runs only in its own goroutine.
type Resyncer struct {
	Runner Runner
	// DesktopConfigPresent gates every cycle; nothing runs without a desktop
	// harness config.
	DesktopConfigPresent func() bool
	// BaseInterval is the timer between checks (DefaultInterval when zero).
	BaseInterval time.Duration
	// StateDir receives the status file for `kei-proxy policy show`; empty
	// disables persistence.
	StateDir string
	Logger   *slog.Logger
	// After is the timer factory. Exported for testing.
	After func(time.Duration) <-chan time.Time
	// Now is the clock. Exported for testing.
	Now func() time.Time

	trigger chan struct{}

	mu          sync.Mutex
	lastBundle  string
	interval    time.Duration
	cycle       int
	rewrittenAt map[string]int
}

// New returns a Resyncer with defaults filled in.
func New(runner Runner, desktopConfigPresent func() bool, baseInterval time.Duration, stateDir string) *Resyncer {
	if baseInterval <= 0 {
		baseInterval = DefaultInterval
	}
	return &Resyncer{
		Runner:               runner,
		DesktopConfigPresent: desktopConfigPresent,
		BaseInterval:         baseInterval,
		StateDir:             stateDir,
		Logger:               slog.Default(),
		After:                time.After,
		Now:                  time.Now,
	}
}

func (r *Resyncer) init() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.trigger == nil {
		r.trigger = make(chan struct{}, 1)
	}
	if r.BaseInterval <= 0 {
		r.BaseInterval = DefaultInterval
	}
	if r.interval == 0 {
		r.interval = r.BaseInterval
	}
	if r.rewrittenAt == nil {
		r.rewrittenAt = map[string]int{}
	}
}

// BundleRefreshed schedules a check when bundleKey (the active bundle's
// identity) differs from the last one seen. It never blocks.
func (r *Resyncer) BundleRefreshed(bundleKey string) {
	r.init()
	r.mu.Lock()
	changed := bundleKey != r.lastBundle
	r.lastBundle = bundleKey
	r.mu.Unlock()
	if !changed {
		return
	}
	select {
	case r.trigger <- struct{}{}:
	default:
	}
}

// Interval is the current timer between checks.
func (r *Resyncer) Interval() time.Duration {
	r.init()
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.interval
}

// Run checks on every bundle change and timer tick until ctx is done.
func (r *Resyncer) Run(ctx context.Context) {
	r.init()
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.trigger:
		case <-r.After(r.Interval()):
		}
		if ctx.Err() != nil {
			return
		}
		r.Cycle(ctx)
	}
}

// Cycle runs one check, and a sync when the check reports drift.
func (r *Resyncer) Cycle(ctx context.Context) {
	r.init()
	if r.DesktopConfigPresent == nil || !r.DesktopConfigPresent() {
		return
	}
	now := r.Now().UTC()
	report, err := r.Runner.Check(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		r.Logger.Warn("harness_resync_failed", "step", "check")
		r.save(Status{LastCheck: now, LastError: "check_failed"})
		return
	}
	status := Status{LastCheck: now, LastDrifted: report.DriftedCount()}
	synced := false
	if report.Drift {
		if err := r.Runner.Sync(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			status.LastError = "sync_failed"
		} else {
			synced = true
			status.LastSync = r.Now().UTC()
		}
	}
	rewritten := r.recordCycle(report)
	interval, backoff := r.backoffState()
	if report.Drift {
		attrs := []any{
			"harnesses", len(report.Harnesses),
			"drifted", report.DriftedCount(),
			"rewritten", rewritten,
			"synced", synced,
			"interval_seconds", int(interval / time.Second),
			"backoff", len(backoff) > 0,
		}
		if synced {
			r.Logger.Info("harness_resync", attrs...)
		} else {
			r.Logger.Warn("harness_resync_failed", append([]any{"step", "sync"}, attrs...)...)
		}
	}
	r.save(status)
}

// recordCycle advances the cycle count and updates the backoff from the
// harnesses another writer rewrote. It returns how many were rewritten.
func (r *Resyncer) recordCycle(report Report) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cycle++
	rewritten, repeat := 0, false
	for _, h := range report.Harnesses {
		if !h.Rewritten() {
			continue
		}
		rewritten++
		if last, ok := r.rewrittenAt[h.Kind]; ok && r.cycle-last <= backoffWindow {
			repeat = true
		}
		r.rewrittenAt[h.Kind] = r.cycle
	}
	for kind, last := range r.rewrittenAt {
		if r.cycle-last >= backoffWindow {
			delete(r.rewrittenAt, kind)
		}
	}
	switch {
	case repeat:
		r.interval = min(r.interval*2, MaxInterval)
	case len(r.rewrittenAt) == 0:
		r.interval = r.BaseInterval
	}
	return rewritten
}

// backoffState returns the interval and the harnesses keeping it raised.
func (r *Resyncer) backoffState() (time.Duration, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.interval <= r.BaseInterval {
		return r.interval, nil
	}
	kinds := make([]string, 0, len(r.rewrittenAt))
	for kind := range r.rewrittenAt {
		kinds = append(kinds, kind)
	}
	slices.Sort(kinds)
	return r.interval, kinds
}

func (r *Resyncer) save(s Status) {
	interval, backoff := r.backoffState()
	s.IntervalSeconds = int(interval / time.Second)
	s.State = StateActive
	if interval > r.BaseInterval {
		s.State = StateBackoff
		s.BackoffKinds = backoff
	}
	if err := SaveStatus(r.StateDir, s); err != nil {
		r.Logger.Warn("harness_resync_state_write_failed")
	}
}
