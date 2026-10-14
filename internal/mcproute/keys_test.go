package mcproute

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestKeyRegistry_Mint_Format(t *testing.T) {
	r := NewKeyRegistry()
	key, err := r.Mint(Session{Subject: "session-1", Agent: "agent-1", HarnessKind: "harness-kind", SessionID: "session-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(key, "kmr_") {
		t.Fatalf("key %q does not start with kmr_", key)
	}
	parts := strings.SplitN(key, "_", 2)
	if len(parts) != 2 {
		t.Fatalf("key %q has no _ separator", key)
	}
	if len(parts[1]) != 43 {
		t.Fatalf("key payload = %d chars, want 43", len(parts[1]))
	}
	for _, c := range parts[1] {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			t.Fatalf("unexpected character %c in key payload", c)
		}
	}
}

func TestKeyRegistry_Validate_ValidKey(t *testing.T) {
	r := NewKeyRegistry()
	key, err := r.Mint(Session{Subject: "session-1", Agent: "agent-1", HarnessKind: "harness-kind", SessionID: "session-1"})
	if err != nil {
		t.Fatal(err)
	}
	sess, ok := r.Validate(key)
	if !ok {
		t.Fatal("expected valid key")
	}
	if sess.Subject != "session-1" {
		t.Fatalf("Subject = %q, want %q", sess.Subject, "session-1")
	}
	if sess.Agent != "agent-1" {
		t.Fatalf("Agent = %q, want %q", sess.Agent, "agent-1")
	}
	if sess.HarnessKind != "harness-kind" {
		t.Fatalf("HarnessKind = %q, want %q", sess.HarnessKind, "harness-kind")
	}
}

func TestKeyRegistry_Validate_InvalidKey(t *testing.T) {
	r := NewKeyRegistry()
	_, ok := r.Validate("kmr_invalidkey123")
	if ok {
		t.Fatal("expected invalid key")
	}
}

func TestKeyRegistry_Validate_BadPrefix(t *testing.T) {
	r := NewKeyRegistry()
	_, ok := r.Validate("not-a-route-key")
	if ok {
		t.Fatal("expected invalid key")
	}
}

func TestKeyRegistry_Validate_EmptyString(t *testing.T) {
	r := NewKeyRegistry()
	_, ok := r.Validate("")
	if ok {
		t.Fatal("expected invalid key")
	}
}

func TestKeyRegistry_Revoke_Session(t *testing.T) {
	r := NewKeyRegistry()
	key1, _ := r.Mint(Session{Subject: "session-1", Agent: "a", HarnessKind: "h", SessionID: "session-1"})
	key2, _ := r.Mint(Session{Subject: "session-1", Agent: "a", HarnessKind: "h", SessionID: "session-1"})
	key3, _ := r.Mint(Session{Subject: "session-2", Agent: "a", HarnessKind: "h", SessionID: "session-2"})

	r.Revoke("session-1")

	if _, ok := r.Validate(key1); ok {
		t.Fatal("key1 should be invalid after revoke")
	}
	if _, ok := r.Validate(key2); ok {
		t.Fatal("key2 should be invalid after revoke")
	}
	if _, ok := r.Validate(key3); !ok {
		t.Fatal("key3 should still be valid (different session)")
	}
}

func TestKeyRegistry_Revoke_UnknownSession(t *testing.T) {
	r := NewKeyRegistry()
	// Should not panic
	r.Revoke("nonexistent-session")
}

func TestKeyRegistry_Expiry(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	r := &KeyRegistry{
		keys:  make(map[string]registryEntry),
		clock: func() time.Time { return now },
	}

	key, _ := r.Mint(Session{Subject: "session-1", Agent: "a", HarnessKind: "h", SessionID: "session-1"})

	if _, ok := r.Validate(key); !ok {
		t.Fatal("key should be valid before expiry")
	}

	now = now.Add(9 * time.Hour)

	if _, ok := r.Validate(key); ok {
		t.Fatal("key should be invalid after 8h expiry")
	}
}

func TestKeyRegistry_Expiry_Boundary(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	r := &KeyRegistry{
		keys:  make(map[string]registryEntry),
		clock: func() time.Time { return now },
	}

	key, _ := r.Mint(Session{Subject: "session-1", Agent: "a", HarnessKind: "h", SessionID: "session-1"})

	// Exactly 8h later should still be valid
	now = now.Add(8 * time.Hour)
	if _, ok := r.Validate(key); !ok {
		t.Fatal("key should be valid exactly at 8h boundary")
	}

	// 1ns past 8h should be invalid
	now = now.Add(1 * time.Nanosecond)
	if _, ok := r.Validate(key); ok {
		t.Fatal("key should be invalid 1ns past 8h boundary")
	}
}

func TestKeyRegistry_NoPlaintextStored(t *testing.T) {
	r := NewKeyRegistry()
	key, _ := r.Mint(Session{Subject: "session-1", Agent: "a", HarnessKind: "h", SessionID: "session-1"})

	h := sha256.Sum256([]byte(key))
	expectedDigest := hex.EncodeToString(h[:])

	r.mu.Lock()
	for storedDigest := range r.keys {
		if storedDigest == key {
			t.Fatal("plaintext key found in internal map")
		}
		if storedDigest != expectedDigest {
			t.Fatalf("stored digest %q does not match expected %q", storedDigest, expectedDigest)
		}
	}
	r.mu.Unlock()
}

func TestKeyRegistry_MultipleKeysSameSession(t *testing.T) {
	r := NewKeyRegistry()
	key1, _ := r.Mint(Session{Subject: "session-1", Agent: "a", HarnessKind: "h", SessionID: "session-1"})
	key2, _ := r.Mint(Session{Subject: "session-1", Agent: "a", HarnessKind: "h", SessionID: "session-1"})

	if _, ok := r.Validate(key1); !ok {
		t.Fatal("key1 should be valid")
	}
	if _, ok := r.Validate(key2); !ok {
		t.Fatal("key2 should be valid")
	}

	r.Revoke("session-1")

	if _, ok := r.Validate(key1); ok {
		t.Fatal("key1 should be invalid after revoke")
	}
	if _, ok := r.Validate(key2); ok {
		t.Fatal("key2 should be invalid after revoke")
	}
}

func TestKeyRegistry_RestartClearsKeys(t *testing.T) {
	r1 := NewKeyRegistry()
	key, _ := r1.Mint(Session{Subject: "session-1", Agent: "a", HarnessKind: "h", SessionID: "session-1"})

	if _, ok := r1.Validate(key); !ok {
		t.Fatal("key should be valid in original registry")
	}

	r2 := NewKeyRegistry()
	if _, ok := r2.Validate(key); ok {
		t.Fatal("key should not be valid in new registry (restart clears)")
	}
}

func TestKeyRegistry_RevokeBySessionID(t *testing.T) {
	r := NewKeyRegistry()
	// One subject with two sessions: ending one session must not revoke the
	// other session's key (ADR-036 §4.4: a key belongs to one session).
	key1, _ := r.Mint(Session{Subject: "alice", Agent: "a", HarnessKind: "h", SessionID: "session-1"})
	key2, _ := r.Mint(Session{Subject: "alice", Agent: "a", HarnessKind: "h", SessionID: "session-2"})

	r.Revoke("session-1")

	if _, ok := r.Validate(key1); ok {
		t.Fatal("session-1 key should be invalid after its session is revoked")
	}
	if _, ok := r.Validate(key2); !ok {
		t.Fatal("session-2 key should stay valid")
	}
}

func TestKeyRegistry_PurgesExpiredKeys(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	r := &KeyRegistry{
		keys:  make(map[string]registryEntry),
		clock: func() time.Time { return now },
	}
	expired, _ := r.Mint(Session{Subject: "alice", Agent: "a", HarnessKind: "h", SessionID: "session-1"})
	_, _ = r.Mint(Session{Subject: "bob", Agent: "a", HarnessKind: "h", SessionID: "session-2"})

	now = now.Add(9 * time.Hour)
	if _, ok := r.Validate(expired); ok {
		t.Fatal("expired key validated")
	}
	_, _ = r.Mint(Session{Subject: "carol", Agent: "a", HarnessKind: "h", SessionID: "session-3"})

	r.mu.Lock()
	n := len(r.keys)
	r.mu.Unlock()
	if n != 1 {
		t.Fatalf("registry holds %d keys, want 1 (expired keys purged)", n)
	}
}
