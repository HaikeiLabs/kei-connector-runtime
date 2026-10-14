package auditcrypto

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestDigestFallsBackToSHA256WhenNoCache(t *testing.T) {
	p := NewProvider("http://unreachable.example", "test-token")
	canonical := []byte(`{"a":1}`)
	digest, keyID := p.Digest(canonical)
	if !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("expected sha256: prefix, got %q", digest)
	}
	if keyID != "" {
		t.Fatalf("expected empty keyID, got %q", keyID)
	}
	sum := sha256.Sum256(canonical)
	if digest != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("digest mismatch: %q", digest)
	}
}

func TestDigestUsesHMACSHA256AfterFetch(t *testing.T) {
	digestKey := make([]byte, 32)
	for i := range digestKey {
		digestKey[i] = 0x42
	}
	srv := newTestServer(t, digestKey, "test-key-1", nil)
	defer srv.Close()

	p := NewProvider(srv.URL, "test-token")
	canonical := []byte(`{"command":"git status"}`)

	digest, keyID := p.Digest(canonical)
	if !strings.HasPrefix(digest, "hmac-sha256:") {
		t.Fatalf("expected hmac-sha256: prefix, got %q", digest)
	}
	if keyID != "test-key-1" {
		t.Fatalf("expected keyID test-key-1, got %q", keyID)
	}

	mac := hmac.New(sha256.New, digestKey)
	mac.Write(canonical)
	want := "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
	if digest != want {
		t.Fatalf("digest:\n  got:  %q\n  want: %q", digest, want)
	}
}

func TestEncryptReturnsEmptyWhenNoRecipients(t *testing.T) {
	p := NewProvider("http://unreachable.example", "test-token")
	ciphertext, keyIDs := p.Encrypt([]byte(`{"a":1}`))
	if ciphertext != "" || keyIDs != nil {
		t.Fatalf("expected empty, got ciphertext=%q keyIDs=%v", ciphertext, keyIDs)
	}
}

func TestEncryptWithNoCustomerRecipientsReturnsEmpty(t *testing.T) {
	digestKey := make([]byte, 32)
	srv := newTestServer(t, digestKey, "dk-1", []Recipient{
		{KeyID: "escrow-1", PublicKey: newTestIdentity(t).Recipient().String(), Kind: "escrow"},
	})
	defer srv.Close()

	p := NewProvider(srv.URL, "test-token")
	ciphertext, keyIDs := p.Encrypt([]byte(`{"a":1}`))
	if ciphertext != "" || keyIDs != nil {
		t.Fatalf("expected empty when no customer recipients, got ciphertext=%q keyIDs=%v", ciphertext, keyIDs)
	}
}

func TestEncryptRoundTripWithSingleRecipient(t *testing.T) {
	id := newTestIdentity(t)
	digestKey := make([]byte, 32)
	srv := newTestServer(t, digestKey, "dk-1", []Recipient{
		{KeyID: "cust-1", PublicKey: id.Recipient().String(), Kind: "customer"},
	})
	defer srv.Close()

	p := NewProvider(srv.URL, "test-token")
	plaintext := []byte(`{"command":"git status"}`)

	ciphertext, keyIDs := p.Encrypt(plaintext)
	if ciphertext == "" {
		t.Fatal("expected non-empty ciphertext")
	}
	if len(keyIDs) != 1 || keyIDs[0] != "cust-1" {
		t.Fatalf("expected keyIDs=[cust-1], got %v", keyIDs)
	}

	got, err := Decrypt(ciphertext, id)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch:\n  got:  %s\n  want: %s", got, plaintext)
	}
}

func TestEncryptRoundTripWithMultiRecipient(t *testing.T) {
	id1 := newTestIdentity(t)
	id2 := newTestIdentity(t)
	digestKey := make([]byte, 32)
	srv := newTestServer(t, digestKey, "dk-1", []Recipient{
		{KeyID: "cust-1", PublicKey: id1.Recipient().String(), Kind: "customer"},
		{KeyID: "cust-2", PublicKey: id2.Recipient().String(), Kind: "customer"},
	})
	defer srv.Close()

	p := NewProvider(srv.URL, "test-token")
	plaintext := []byte(`{"command":"git diff"}`)

	ciphertext, keyIDs := p.Encrypt(plaintext)
	if ciphertext == "" {
		t.Fatal("expected non-empty ciphertext")
	}
	if len(keyIDs) != 2 {
		t.Fatalf("expected 2 keyIDs, got %v", keyIDs)
	}

	got, err := Decrypt(ciphertext, id1)
	if err != nil {
		t.Fatalf("decrypt with id1 failed: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch with id1:\n  got:  %s\n  want: %s", got, plaintext)
	}

	got2, err := Decrypt(ciphertext, id2)
	if err != nil {
		t.Fatalf("decrypt with id2 failed: %v", err)
	}
	if !bytes.Equal(got2, plaintext) {
		t.Fatalf("plaintext mismatch with id2:\n  got:  %s\n  want: %s", got2, plaintext)
	}
}

func TestDecryptWithWrongIdentityFails(t *testing.T) {
	id := newTestIdentity(t)
	wrongID := newTestIdentity(t)
	digestKey := make([]byte, 32)
	srv := newTestServer(t, digestKey, "dk-1", []Recipient{
		{KeyID: "cust-1", PublicKey: id.Recipient().String(), Kind: "customer"},
	})
	defer srv.Close()

	p := NewProvider(srv.URL, "test-token")
	plaintext := []byte(`{"command":"git status"}`)

	ciphertext, _ := p.Encrypt(plaintext)
	if ciphertext == "" {
		t.Fatal("expected non-empty ciphertext")
	}

	_, err := Decrypt(ciphertext, wrongID)
	if err == nil {
		t.Fatal("expected error decrypting with wrong identity")
	}
}

func TestEncryptFailsOpenWhenRecipientPublicKeyInvalid(t *testing.T) {
	digestKey := make([]byte, 32)
	srv := newTestServer(t, digestKey, "dk-1", []Recipient{
		{KeyID: "bad", PublicKey: "age1not-valid", Kind: "customer"},
	})
	defer srv.Close()

	p := NewProvider(srv.URL, "test-token")
	ciphertext, keyIDs := p.Encrypt([]byte(`{"a":1}`))
	if ciphertext != "" || keyIDs != nil {
		t.Fatalf("expected empty on bad recipient key, got ciphertext=%q keyIDs=%v", ciphertext, keyIDs)
	}
}

func TestCacheRespectedWithinTTL(t *testing.T) {
	digestKey := make([]byte, 32)
	for i := range digestKey {
		digestKey[i] = 0x42
	}
	var callCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(fetchResponse{
			Recipients:  []Recipient{},
			DigestKeyID: "dk-1",
			DigestKey:   base64.StdEncoding.EncodeToString(digestKey),
			ExpiresAt:   "2099-01-01T00:00:00Z",
		})
	}))
	defer srv.Close()

	p := NewProvider(srv.URL, "test-token")
	// First call: fetch succeeds and caches.
	_ = p.ensureFresh(context.Background())
	// Second call: cache is still fresh (expiresAt is far future), no refetch.
	_ = p.ensureFresh(context.Background())

	if callCount != 1 {
		t.Fatalf("expected 1 call (cached), got %d", callCount)
	}
}

// --- helpers ---

func newTestIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

func newTestServer(t *testing.T, digestKey []byte, digestKeyID string, recipients []Recipient) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(fetchResponse{
			Recipients:  recipients,
			DigestKeyID: digestKeyID,
			DigestKey:   base64.StdEncoding.EncodeToString(digestKey),
			ExpiresAt:   "2099-01-01T00:00:00Z",
		})
	}))
}

// A failed fetch is not retried on every call: the MCP route digests and
// encrypts on the request path, so an unreachable control plane must not add
// a fetch timeout to each tools/call (HAI-488).
func TestProviderBacksOffAfterAFailedFetch(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	p := NewProvider(srv.URL, "test-token")

	for i := 0; i < 3; i++ {
		p.Digest([]byte(`{}`))
		p.Encrypt([]byte(`{}`))
	}
	if hits != 1 {
		t.Fatalf("control plane fetched %d times after a failure, want 1 until the backoff passes", hits)
	}
}
