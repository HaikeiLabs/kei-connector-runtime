package invoke

// SecretCache holds the credentials of shared opaque_ref connectors in the
// serve daemon's memory (HAI-1071), so an allowed call never waits on the
// tenant secret store. The owner rule: an agent never blocks on a
// synchronous external call.
//
//   - Prefetch: every shared opaque_ref connector in the bundle is loaded
//     when a session starts (if not already held) and whenever the bundle
//     syncs (SetConnectors).
//   - Calls: Resolve reads memory only. A connector that is not loaded, or
//     whose last load failed, denies credential_unavailable (or the load's
//     own reason code) at once.
//   - Refresh: Run reloads each value every RefreshInterval and retries a
//     failed load with exponential backoff. A failed refresh keeps the value
//     already held, so a store outage does not break running sessions.
//   - Drop: a value is dropped when its connector leaves the bundle, when its
//     reference (credential_ref, credential_backend) changes, and when the
//     last live session ends. Flush drops everything.
//
// Values live only in this struct: they are never written to disk, logged,
// formatted, or part of an error.

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

// Default refresh cadence and retry backoff bounds.
const (
	DefaultSecretRefreshInterval = 5 * time.Minute
	DefaultSecretMinBackoff      = time.Second
	DefaultSecretMaxBackoff      = 5 * time.Minute
)

// SecretCacheOptions tunes a SecretCache; zero values take the defaults.
type SecretCacheOptions struct {
	RefreshInterval time.Duration
	MinBackoff      time.Duration
	MaxBackoff      time.Duration
	Now             func() time.Time
}

// SecretCache is the daemon's in-memory store of shared connector
// credentials. The zero value is not usable; call NewSecretCache.
type SecretCache struct {
	resolver SecretResolver
	opts     SecretCacheOptions
	wake     chan struct{}

	mu       sync.Mutex
	entries  map[string]*secretEntry // by connector id
	sessions map[string]struct{}
	// epoch increments on every drop, so a load that started before a drop
	// cannot store its value after it.
	epoch uint64
}

// secretEntry is one connector's cached credential and load state.
type secretEntry struct {
	connector   policybundle.Connector
	fingerprint string
	value       string
	loaded      bool
	err         *SecretError
	failures    int
	nextAttempt time.Time
	loading     bool
}

// NewSecretCache returns a cache that loads values through r.
func NewSecretCache(r SecretResolver, opts SecretCacheOptions) *SecretCache {
	if opts.RefreshInterval <= 0 {
		opts.RefreshInterval = DefaultSecretRefreshInterval
	}
	if opts.MinBackoff <= 0 {
		opts.MinBackoff = DefaultSecretMinBackoff
	}
	if opts.MaxBackoff < opts.MinBackoff {
		opts.MaxBackoff = max(DefaultSecretMaxBackoff, opts.MinBackoff)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &SecretCache{
		resolver: r,
		opts:     opts,
		wake:     make(chan struct{}, 1),
		entries:  map[string]*secretEntry{},
		sessions: map[string]struct{}{},
	}
}

// String and GoString keep a formatted cache from printing a value.
func (c *SecretCache) String() string   { return "invoke.SecretCache{[REDACTED]}" }
func (c *SecretCache) GoString() string { return c.String() }

// cachedShared reports whether c's credential is cached: a shared
// connector whose credential is tenant-stored.
func cachedShared(c policybundle.Connector) bool {
	return contract.CredentialSource(c.CredentialSource) == contract.CredentialSourceOpaqueRef &&
		contract.AccountModel(c.AccountModel) == contract.AccountModelShared
}

// fingerprint identifies the credential a descriptor points at; a change
// drops the value.
func fingerprint(c policybundle.Connector) string {
	return c.CredentialBackend + "\x00" + c.CredentialRef
}

// SetConnectors replaces the set of cached connectors with the bundle's
// shared opaque_ref connectors. Values of removed connectors, or of
// connectors whose reference changed, are dropped. Every remaining entry is
// due for a refresh, so a bundle change picks up rotated secrets; the
// refresh runs in the background (Run).
func (c *SecretCache) SetConnectors(connectors []policybundle.Connector) {
	c.mu.Lock()
	desired := map[string]policybundle.Connector{}
	for _, conn := range connectors {
		if cachedShared(conn) {
			desired[conn.ID] = conn
		}
	}
	for id, e := range c.entries {
		conn, ok := desired[id]
		if !ok || fingerprint(conn) != e.fingerprint {
			c.dropLocked(id)
		}
	}
	now := c.opts.Now()
	for id, conn := range desired {
		if e, ok := c.entries[id]; ok {
			e.connector, e.nextAttempt, e.failures = conn, now, 0
			continue
		}
		c.entries[id] = &secretEntry{connector: conn, fingerprint: fingerprint(conn), nextAttempt: now}
	}
	c.mu.Unlock()
	c.signal()
}

// dropLocked zeroes and removes connector id's entry.
func (c *SecretCache) dropLocked(id string) {
	if e, ok := c.entries[id]; ok {
		e.value, e.loaded = "", false
		delete(c.entries, id)
	}
	c.epoch++
}

// SessionStarted records a live session and loads every connector that is
// not held yet, bounded by the resolver's per-read timeout. It runs once per
// session, before the session's first call, so calls read memory only.
func (c *SecretCache) SessionStarted(ctx context.Context, id string) {
	c.mu.Lock()
	c.sessions[id] = struct{}{}
	now := c.opts.Now()
	for _, e := range c.entries {
		if !e.loaded && e.err == nil {
			e.nextAttempt = now
		}
	}
	c.mu.Unlock()
	c.Refresh(ctx)
}

// SessionEnded forgets a session; when no session is live, every value is
// dropped. The entries stay, so the next session start loads them again.
func (c *SecretCache) SessionEnded(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.sessions, id)
	if len(c.sessions) == 0 {
		c.clearLocked()
	}
}

// Flush drops every value and forgets every session (daemon exit, runtime
// revocation).
func (c *SecretCache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessions = map[string]struct{}{}
	c.clearLocked()
}

func (c *SecretCache) clearLocked() {
	now := c.opts.Now()
	for _, e := range c.entries {
		e.value, e.loaded, e.err, e.failures, e.nextAttempt = "", false, nil, 0, now
	}
	c.epoch++
}

// held is the number of values in memory (tests).
func (c *SecretCache) held() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, e := range c.entries {
		if e.loaded {
			n++
		}
	}
	return n
}

// Resolve returns connector conn's credential from memory, or a
// *SecretError. It never reads the secret store: a connector that is not
// loaded denies at once. A connector the cache does not hold (not shared,
// not opaque_ref) is resolved by the resolver directly, as before HAI-1071;
// the daemon releases tenant-stored credentials only for shared connectors.
func (c *SecretCache) Resolve(ctx context.Context, conn policybundle.Connector) (string, error) {
	if !cachedShared(conn) {
		return c.resolver.Resolve(ctx, conn)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[conn.ID]
	switch {
	case !ok || e.fingerprint != fingerprint(conn):
		return "", &SecretError{"credential_unavailable", "the connector credential is not loaded"}
	case e.loaded:
		return e.value, nil
	case e.err != nil:
		return "", &SecretError{e.err.Code, e.err.Reason}
	}
	return "", &SecretError{"credential_unavailable", "the connector credential is not loaded"}
}

// CheckExternalField checks an external reference against the local
// connector reference index; it reads no secret.
func (c *SecretCache) CheckExternalField(conn policybundle.Connector, field string) error {
	return c.resolver.CheckExternalField(conn, field)
}

// signal wakes Run without blocking.
func (c *SecretCache) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// Run refreshes due entries in the background until ctx is done: on every
// SetConnectors, and at each entry's next refresh or retry time.
func (c *SecretCache) Run(ctx context.Context) {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		c.Refresh(ctx)
		wait := c.nextWait()
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wait)
		select {
		case <-ctx.Done():
			return
		case <-c.wake:
		case <-timer.C:
		}
	}
}

// nextWait is how long until the earliest due entry, capped at the refresh
// interval.
func (c *SecretCache) nextWait() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	wait := c.opts.RefreshInterval
	if len(c.sessions) == 0 {
		return wait
	}
	now := c.opts.Now()
	for _, e := range c.entries {
		if d := e.nextAttempt.Sub(now); d < wait {
			wait = d
		}
	}
	return max(wait, 10*time.Millisecond)
}

// Refresh loads every due entry now, concurrently, and waits for the loads.
// With no live session nothing is loaded.
func (c *SecretCache) Refresh(ctx context.Context) {
	c.mu.Lock()
	if len(c.sessions) == 0 {
		c.mu.Unlock()
		return
	}
	now := c.opts.Now()
	epoch := c.epoch
	var due []*secretEntry
	for _, e := range c.entries {
		if !e.loading && !now.Before(e.nextAttempt) {
			e.loading = true
			due = append(due, e)
		}
	}
	c.mu.Unlock()

	var wg sync.WaitGroup
	for _, e := range due {
		wg.Add(1)
		go func(e *secretEntry) {
			defer wg.Done()
			c.load(ctx, e, epoch)
		}(e)
	}
	wg.Wait()
}

// load reads one entry's value through the resolver and records the result.
func (c *SecretCache) load(ctx context.Context, e *secretEntry, epoch uint64) {
	c.mu.Lock()
	conn := e.connector
	c.mu.Unlock()
	value, err := c.resolver.Resolve(ctx, conn)

	c.mu.Lock()
	defer c.mu.Unlock()
	e.loading = false
	current, ok := c.entries[conn.ID]
	if !ok || current != e || c.epoch != epoch || len(c.sessions) == 0 {
		// Dropped, replaced or the last session ended while loading.
		return
	}
	now := c.opts.Now()
	if err == nil {
		e.value, e.loaded, e.err, e.failures = value, true, nil, 0
		e.nextAttempt = now.Add(c.opts.RefreshInterval)
		return
	}
	se, isSecretErr := err.(*SecretError)
	if !isSecretErr {
		se = &SecretError{"credential_unavailable", "the connector credential is not available"}
	}
	e.failures++
	e.nextAttempt = now.Add(c.backoff(e.failures))
	if e.loaded && se.Code == "credential_unavailable" {
		// A store outage: keep serving the value already loaded.
		slog.Warn("shared_credential_refresh_failed", "connector_id", conn.ID, "reason_code", se.Code, "failures", e.failures, "kept_loaded_value", true)
		return
	}
	// The descriptor or index no longer resolves: drop any held value.
	e.value, e.loaded, e.err = "", false, se
	slog.Warn("shared_credential_load_failed", "connector_id", conn.ID, "reason_code", se.Code, "failures", e.failures)
}

// backoff is the retry delay after n consecutive failures.
func (c *SecretCache) backoff(n int) time.Duration {
	d := c.opts.MinBackoff
	for i := 1; i < n && d < c.opts.MaxBackoff; i++ {
		d *= 2
	}
	return min(d, c.opts.MaxBackoff)
}
