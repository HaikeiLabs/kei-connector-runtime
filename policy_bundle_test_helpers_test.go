package connectorruntime

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

func signedExampleBundle(t *testing.T, now time.Time) ([]byte, policybundle.KeySet) {
	t.Helper()
	envelopeBytes, err := os.ReadFile("docs/contracts/examples/policy-bundle-v1.envelope.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var envelope policybundle.Envelope
	if err := json.Unmarshal(envelopeBytes, &envelope); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload = bytes.ReplaceAll(payload, []byte("2026-09-28T16:00:00Z"), []byte(now.UTC().Format(time.RFC3339)))
	payload = bytes.ReplaceAll(payload, []byte("2026-09-29T04:00:00Z"), []byte(now.UTC().Add(12*time.Hour).Format(time.RFC3339)))
	payload = bytes.ReplaceAll(payload, []byte("search_web"), []byte("web_search"))
	seed := sha256.Sum256([]byte("kei.policy-bundle/v1 example signing key - public test seed, NOT A SECRET"))
	private := ed25519.NewKeyFromSeed(seed[:])
	public := private.Public().(ed25519.PublicKey)
	if got := base64.RawURLEncoding.EncodeToString(public); got != "W5NclXraIJdyUtLqIHtaY7XfnhskAmqiub36Tgt_ye8" {
		t.Fatalf("public example key mismatch: %s", got)
	}
	pae := []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len([]byte(envelope.PayloadType)), envelope.PayloadType, len(payload), payload))
	envelope.Payload = base64.StdEncoding.EncodeToString(payload)
	envelope.Signatures[0].Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(private, pae))
	out, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	keys := policybundle.KeySet{Keys: []policybundle.Key{{KTY: "OKP", CRV: "Ed25519", X: base64.RawURLEncoding.EncodeToString(public), KID: "kei-pb-000000-01", Use: "sig", Alg: "EdDSA", Status: "active"}}}
	return out, keys
}

func mustActivateTestBundle(t *testing.T, dir string, now time.Time) (*policybundle.Verified, *policybundle.Store) {
	t.Helper()
	env, keys := signedExampleBundle(t, now)
	store, err := policybundle.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PinKeys(keys); err != nil {
		t.Fatal(err)
	}
	bundle, err := store.Activate(env, "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", now, false)
	if err != nil {
		t.Fatal(err)
	}
	return bundle, store
}

func fixtureBundlePayloadForTest(t *testing.T, now time.Time) []byte {
	t.Helper()
	env, _ := signedExampleBundle(t, now)
	var e policybundle.Envelope
	if err := json.Unmarshal(env, &e); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"name": "web_search"`) {
		t.Fatal("test bundle did not use requested web_search mapping")
	}
	return payload
}
