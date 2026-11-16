package runtime

// Shared connector credentials in daemon memory (HAI-1071). The daemon owns
// one invoke.SecretCache: it is told the bundle's connectors on every bundle
// change, prefetches when a session starts, refreshes in the background, and
// drops its values when the last session ends. POST /v1/credentials:release
// and POST /v1/commands:run read it instead of the tenant secret store, so an
// allowed call never waits on a synchronous external read.

import (
	"context"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/invoke"
)

// ownerSecretHolder is the cache holder for the tokenless owner session. The
// owner session is recreated on every bundle refresh; a stable holder keeps
// those recreations from dropping and reloading the shared values.
const ownerSecretHolder = "\x00owner"

// SetConnectorSecrets sets the tenant secret store reader for shared
// opaque_ref connectors (HAI-1066): the connector reference index that
// `kei-proxy credential sync` wrote, and the KEI_SECRETS_BACKEND store. The
// daemon serves their values from memory (HAI-1071) and refreshes them in the
// background until Close. Without one, those releases deny
// credential_unavailable.
func (l *LocalPDP) SetConnectorSecrets(r invoke.SecretResolver) {
	cache := invoke.NewSecretCache(r, invoke.SecretCacheOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	l.secretsMu.Lock()
	if l.stopSecrets != nil {
		l.stopSecrets()
	}
	l.secrets, l.stopSecrets, l.secretsDigest = cache, cancel, ""
	l.secretsMu.Unlock()
	go cache.Run(ctx)
	l.syncSecretConnectors()
}

// ConnectorSecrets is the daemon's shared credential cache, or nil.
func (l *LocalPDP) ConnectorSecrets() *invoke.SecretCache {
	l.secretsMu.Lock()
	defer l.secretsMu.Unlock()
	return l.secrets
}

// syncSecretConnectors hands the verified bundle's connectors to the cache
// when the bundle changed since the last call.
func (l *LocalPDP) syncSecretConnectors() {
	cache := l.ConnectorSecrets()
	e := l.evaluator.Load()
	if cache == nil || e == nil {
		return
	}
	verified, ok := e.Bundle()
	if !ok {
		return
	}
	l.secretsMu.Lock()
	changed := verified.Digest != l.secretsDigest
	l.secretsDigest = verified.Digest
	l.secretsMu.Unlock()
	if changed {
		cache.SetConnectors(verified.Connectors())
	}
}

// prefetchSharedSecrets registers holder as a live session and loads every
// shared connector credential not held yet, before the session's first call.
func (l *LocalPDP) prefetchSharedSecrets(ctx context.Context, holder string) {
	cache := l.ConnectorSecrets()
	if cache == nil {
		return
	}
	l.syncSecretConnectors()
	cache.SessionStarted(ctx, holder)
}

// releaseSharedSecrets forgets holder; the last one drops every value.
func (l *LocalPDP) releaseSharedSecrets(holder string) {
	if cache := l.ConnectorSecrets(); cache != nil {
		cache.SessionEnded(holder)
	}
}

// stopConnectorSecrets ends the background refresh and drops every value.
func (l *LocalPDP) stopConnectorSecrets() {
	l.secretsMu.Lock()
	cache, stop := l.secrets, l.stopSecrets
	l.stopSecrets = nil
	l.secretsMu.Unlock()
	if stop != nil {
		stop()
	}
	if cache != nil {
		cache.Flush()
	}
}

// flushConnectorSecrets drops every value; the background refresh keeps
// running and the next session start reloads.
func (l *LocalPDP) flushConnectorSecrets() {
	if cache := l.ConnectorSecrets(); cache != nil {
		cache.Flush()
	}
}
