package mcproute

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	routeKeyPrefix = "kmr_"
	routeKeyExpiry = 8 * time.Hour
	routeKeyRawLen = 32
)

type registryEntry struct {
	session Session
	expiry  time.Time
}

// KeyRegistry holds the route keys of live MCP sessions (ADR-036 §4.4).
// A key belongs to exactly one named session. Keys are random, stored only
// as SHA-256 digests, and stop validating when their session is revoked,
// after 8 hours, or when the daemon restarts (the registry is memory only).
// Expired entries are purged on every Mint and Validate.
type KeyRegistry struct {
	mu    sync.Mutex
	keys  map[string]registryEntry
	clock func() time.Time
}

// NewKeyRegistry creates an empty key registry.
func NewKeyRegistry() *KeyRegistry {
	return &KeyRegistry{
		keys:  make(map[string]registryEntry),
		clock: time.Now,
	}
}

// Mint generates a new route key for s and returns it in the form
// kmr_<43 base64url characters>. Only its digest is kept.
func (r *KeyRegistry) Mint(s Session) (string, error) {
	buf := make([]byte, routeKeyRawLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("mint route key: %w", err)
	}
	key := routeKeyPrefix + base64.RawURLEncoding.EncodeToString(buf)

	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clock()
	r.purgeLocked(now)
	r.keys[sha256Hex([]byte(key))] = registryEntry{session: s, expiry: now.Add(routeKeyExpiry)}
	return key, nil
}

// Validate returns the session a route key belongs to, if the key is known
// and not expired.
func (r *KeyRegistry) Validate(key string) (*Session, bool) {
	if !strings.HasPrefix(key, routeKeyPrefix) {
		return nil, false
	}
	digest := sha256Hex([]byte(key))

	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clock()
	r.purgeLocked(now)
	entry, ok := r.keys[digest]
	if !ok {
		return nil, false
	}
	s := entry.session
	return &s, true
}

// Revoke removes every key minted for sessionID. The daemon calls it when
// the session ends for any reason.
func (r *KeyRegistry) Revoke(sessionID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for digest, entry := range r.keys {
		if entry.session.SessionID == sessionID {
			delete(r.keys, digest)
		}
	}
}

// purgeLocked drops every key past its expiry. r.mu must be held.
func (r *KeyRegistry) purgeLocked(now time.Time) {
	for digest, entry := range r.keys {
		if now.After(entry.expiry) {
			delete(r.keys, digest)
		}
	}
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
