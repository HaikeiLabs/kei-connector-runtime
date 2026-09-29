// Package crypto holds the KMP1 credential-delivery envelope: X25519 key
// agreement, a SHA-256 derived AES-256-GCM key, and the runtime installation
// and recipient key id bound as associated data. It is pure computation — no
// network, file, or environment access — so it can be audited on its own.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	envelopeMagic = "KMP1"
	// kdfLabel domain-separates the envelope key. It predates connector
	// secrets and is shared with cmd/web, so it keeps its model-profile name.
	kdfLabel = "kei-model-profile-envelope-v1\x00"
)

var errInvalidPrivateKey = errors.New("invalid credential sync private key")

// ParsePrivateKey decodes a base64 (raw or padded) 32-byte X25519 private key.
// The error never includes the encoded key.
func ParsePrivateKey(encoded string) (*ecdh.PrivateKey, error) {
	raw, err := decodeBase64(encoded)
	if err != nil || len(raw) != 32 {
		return nil, errInvalidPrivateKey
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, errInvalidPrivateKey
	}
	return key, nil
}

// PublicKey returns the raw-base64 public key for an encoded private key: the
// value the runtime registers so the control plane can seal deliveries to it.
func PublicKey(encodedPrivateKey string) (string, error) {
	key, err := ParsePrivateKey(encodedPrivateKey)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// Seal builds a KMP1 envelope for plaintext addressed to recipient, bound to
// installationID and keyID. The control plane (cmd/web) is the production
// sealer; this is its inverse of Open, kept beside it so the format has one
// definition in the runtime.
func Seal(plaintext string, recipient *ecdh.PublicKey, installationID, keyID string) (string, error) {
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("seal credential delivery")
	}
	gcm, err := envelopeAEAD(ephemeral, recipient)
	if err != nil {
		return "", fmt.Errorf("seal credential delivery")
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("seal credential delivery")
	}
	payload := append([]byte(envelopeMagic), ephemeral.PublicKey().Bytes()...)
	payload = append(payload, nonce...)
	payload = gcm.Seal(payload, nonce, []byte(plaintext), associatedData(installationID, keyID))
	return base64.RawStdEncoding.EncodeToString(payload), nil
}

// Open authenticates and decrypts a KMP1 envelope sealed to key for
// installationID and keyID. Errors are fixed strings: they never carry the
// envelope, the key, or the plaintext.
func Open(sealed string, key *ecdh.PrivateKey, installationID, keyID string) (string, error) {
	payload, err := decodeBase64(sealed)
	if err != nil || len(payload) < 4+32+12+16 || string(payload[:4]) != envelopeMagic {
		return "", fmt.Errorf("invalid credential delivery envelope")
	}
	ephemeral, err := ecdh.X25519().NewPublicKey(payload[4:36])
	if err != nil {
		return "", fmt.Errorf("invalid credential delivery envelope")
	}
	gcm, err := envelopeAEAD(key, ephemeral)
	if err != nil {
		return "", fmt.Errorf("decrypt credential delivery")
	}
	nonceEnd := 36 + gcm.NonceSize()
	plaintext, err := gcm.Open(nil, payload[36:nonceEnd], payload[nonceEnd:], associatedData(installationID, keyID))
	if err != nil || len(plaintext) == 0 {
		return "", fmt.Errorf("credential delivery authentication failed")
	}
	return string(plaintext), nil
}

func envelopeAEAD(private *ecdh.PrivateKey, public *ecdh.PublicKey) (cipher.AEAD, error) {
	shared, err := private.ECDH(public)
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256(append([]byte(kdfLabel), shared...))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func associatedData(installationID, keyID string) []byte {
	return []byte(installationID + "\x00" + keyID)
}

func decodeBase64(s string) ([]byte, error) {
	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.StdEncoding.DecodeString(s)
	}
	return b, err
}
