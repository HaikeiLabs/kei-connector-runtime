package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func newKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// sealByHand builds a KMP1 envelope without Seal, so the wire format cmd/web
// emits is pinned independently of this package's own sealing code.
func sealByHand(t *testing.T, plaintext string, recipient *ecdh.PublicKey, installationID, keyID string) string {
	t.Helper()
	ephemeralKey := newKey(t)
	shared, err := ephemeralKey.ECDH(recipient)
	if err != nil {
		t.Fatal(err)
	}
	key := sha256.Sum256(append([]byte("kei-model-profile-envelope-v1\x00"), shared...))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), []byte(installationID+"\x00"+keyID))
	payload := append([]byte("KMP1"), ephemeralKey.PublicKey().Bytes()...)
	payload = append(payload, nonce...)
	payload = append(payload, ciphertext...)
	return base64.RawStdEncoding.EncodeToString(payload)
}

func TestOpenKMP1(t *testing.T) {
	key := newKey(t)
	sealed := sealByHand(t, "provider-secret", key.PublicKey(), "runtime-1", "key-1")

	plaintext, err := Open(sealed, key, "runtime-1", "key-1")
	if err != nil || plaintext != "provider-secret" {
		t.Fatalf("Open = %q, %v", plaintext, err)
	}
	// The installation and key id are bound as associated data.
	if _, err := Open(sealed, key, "runtime-2", "key-1"); err == nil {
		t.Fatal("Open accepted another installation")
	}
	if _, err := Open(sealed, key, "runtime-1", "key-2"); err == nil {
		t.Fatal("Open accepted another key id")
	}
	if _, err := Open(sealed, newKey(t), "runtime-1", "key-1"); err == nil {
		t.Fatal("Open accepted another private key")
	}
}

func TestOpenAcceptsPaddedBase64(t *testing.T) {
	key := newKey(t)
	raw, _ := base64.RawStdEncoding.DecodeString(sealByHand(t, "v", key.PublicKey(), "r", "k"))
	if got, err := Open(base64.StdEncoding.EncodeToString(raw), key, "r", "k"); err != nil || got != "v" {
		t.Fatalf("Open(padded) = %q, %v", got, err)
	}
}

func TestOpenRejectsMalformedEnvelopes(t *testing.T) {
	key := newKey(t)
	valid, _ := base64.RawStdEncoding.DecodeString(sealByHand(t, "v", key.PublicKey(), "r", "k"))
	wrongMagic := append([]byte("KMP2"), valid[4:]...)
	tampered := append([]byte{}, valid...)
	tampered[len(tampered)-1] ^= 1
	for name, sealed := range map[string]string{
		"not base64":  "!!!",
		"too short":   base64.RawStdEncoding.EncodeToString(valid[:40]),
		"wrong magic": base64.RawStdEncoding.EncodeToString(wrongMagic),
		"tampered":    base64.RawStdEncoding.EncodeToString(tampered),
	} {
		if _, err := Open(sealed, key, "r", "k"); err == nil {
			t.Errorf("%s: Open succeeded", name)
		}
	}
	empty := sealByHand(t, "", key.PublicKey(), "r", "k")
	if _, err := Open(empty, key, "r", "k"); err == nil {
		t.Error("Open accepted an empty plaintext")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := newKey(t)
	sealed, err := Seal("round-trip-secret", key.PublicKey(), "runtime-1", "key-1")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "round-trip-secret") {
		t.Fatal("sealed envelope carries the plaintext")
	}
	if got, err := Open(sealed, key, "runtime-1", "key-1"); err != nil || got != "round-trip-secret" {
		t.Fatalf("Open(Seal) = %q, %v", got, err)
	}
}

func TestParsePrivateKey(t *testing.T) {
	key := newKey(t)
	for _, encoded := range []string{
		base64.RawStdEncoding.EncodeToString(key.Bytes()),
		base64.StdEncoding.EncodeToString(key.Bytes()),
	} {
		parsed, err := ParsePrivateKey(encoded)
		if err != nil || !parsed.Equal(key) {
			t.Fatalf("ParsePrivateKey(%q) = %v", encoded, err)
		}
	}
	for _, encoded := range []string{"", "!!!", base64.RawStdEncoding.EncodeToString(make([]byte, 31))} {
		if _, err := ParsePrivateKey(encoded); err == nil || err.Error() != "invalid credential sync private key" {
			t.Errorf("ParsePrivateKey(%q) = %v", encoded, err)
		}
	}
}

func TestPublicKey(t *testing.T) {
	key := newKey(t)
	got, err := PublicKey(base64.StdEncoding.EncodeToString(key.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if want := base64.RawStdEncoding.EncodeToString(key.PublicKey().Bytes()); got != want {
		t.Fatalf("PublicKey = %q, want %q", got, want)
	}
	if _, err := PublicKey("short"); err == nil {
		t.Fatal("PublicKey accepted an invalid private key")
	}
}
