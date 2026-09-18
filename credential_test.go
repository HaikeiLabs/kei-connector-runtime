package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestDecryptDeliveryPayloadKMP1(t *testing.T) {
	curve := ecdh.X25519()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ephemeralKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := ephemeralKey.ECDH(privateKey.PublicKey())
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
	runtimeID, keyID := "runtime-1", "key-1"
	ciphertext := gcm.Seal(nil, nonce, []byte("provider-secret"), []byte(runtimeID+"\x00"+keyID))
	payload := append([]byte("KMP1"), ephemeralKey.PublicKey().Bytes()...)
	payload = append(payload, nonce...)
	payload = append(payload, ciphertext...)

	plaintext, err := decryptDeliveryPayload(
		base64.RawStdEncoding.EncodeToString(payload), runtimeID, keyID, keyID,
		base64.RawStdEncoding.EncodeToString(privateKey.Bytes()),
	)
	if err != nil || plaintext != "provider-secret" {
		t.Fatalf("decrypt result plaintext=%q err=%v", plaintext, err)
	}
	if _, err := decryptDeliveryPayload(base64.RawStdEncoding.EncodeToString(payload), runtimeID, keyID, "other-key", base64.RawStdEncoding.EncodeToString(privateKey.Bytes())); err == nil {
		t.Fatal("decrypt accepted a mismatched key id")
	}
}
