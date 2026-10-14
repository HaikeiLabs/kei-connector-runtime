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
	subject     string
	sessionID   string
	agent       string
	harnessKind string
	expiry      time.Time
}

// KeyRegistry manages one-time route keys for MCP sessions.
// Keys are randomly generated, stored only as SHA-256 digests,
// and expire after 8 hours. A restart clears all keys.
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

// Mint generates a new route key for the given session, agent, and harness
// kind. Returns the plaintext key in the format kmr_<43-base64url-chars>.
// The agent and harnessKind parameters are accepted for future audit tracking
// but are not stored.
func (r *KeyRegistry) Mint(subject, agent, harnessKind, sessionID string) (string, error) {
	buf := make([]byte, routeKeyRawLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("mint route key: %w", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(buf)
	key := routeKeyPrefix + payload

	digest := sha256Hex([]byte(key))

	r.mu.Lock()
	r.keys[digest] = registryEntry{
		subject:     subject,
		sessionID:   sessionID,
		agent:       agent,
		harnessKind: harnessKind,
		expiry:      r.clock().Add(routeKeyExpiry),
	}
	r.mu.Unlock()

	return key, nil
}

// Validate checks a route key and returns the associated session
// if the key is valid (known and not expired).
func (r *KeyRegistry) Validate(key string) (*Session, bool) {
	if !strings.HasPrefix(key, routeKeyPrefix) {
		return nil, false
	}

	digest := sha256Hex([]byte(key))

	r.mu.Lock()
	entry, ok := r.keys[digest]
	r.mu.Unlock()

	if !ok {
		return nil, false
	}

	if r.clock().After(entry.expiry) {
		return nil, false
	}

	return &Session{
		Subject:     entry.subject,
		SessionID:   entry.sessionID,
		Agent:       entry.agent,
		HarnessKind: entry.harnessKind,
	}, true
}

// Revoke removes all keys associated with the given session ID.
func (r *KeyRegistry) Revoke(subject string) {
	r.mu.Lock()
	for digest, entry := range r.keys {
		if entry.subject == subject {
			delete(r.keys, digest)
		}
	}
	r.mu.Unlock()
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
