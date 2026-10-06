package credentials

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/crypto"
)

// fakeStore is a secrets.Store that records calls and returns canned values.
type fakeStore struct {
	value     string
	putErr    error
	putCalled bool
	lastRef   string
}

func (f *fakeStore) Get(ctx context.Context, backend, ref string) (*string, error) {
	f.lastRef = ref
	v := f.value
	return &v, nil
}

func (f *fakeStore) Put(ctx context.Context, backend, ref, value string) error {
	f.putCalled = true
	f.lastRef = ref
	return f.putErr
}

func (f *fakeStore) Delete(ctx context.Context, backend, ref string) error { return nil }

func (f *fakeStore) Validate(ctx context.Context, backend, ref string) error {
	_, err := f.Get(ctx, backend, ref)
	return err
}

// sealKMP1 seals plaintext to the public half of the 32-byte X25519 private
// key, as the control plane does.
func sealKMP1(t *testing.T, plaintext, runtimeID, keyID string, privKeyBytes []byte) string {
	t.Helper()
	key, err := ecdh.X25519().NewPrivateKey(privKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := crypto.Seal(plaintext, key.PublicKey(), runtimeID, keyID)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func fixedInstallation(id string) InstallationResolver {
	return func(context.Context) (string, error) { return id, nil }
}

func newPrivateKey(t *testing.T) []byte {
	t.Helper()
	privKey := make([]byte, 32)
	if _, err := rand.Read(privKey); err != nil {
		t.Fatal(err)
	}
	return privKey
}

// newSyncControlPlane stands up a control plane that serves one delivery for
// the given sealed payload and records the ack body.
func newSyncControlPlane(t *testing.T, keyID, sealed, secretRef string) (*httptest.Server, *[]byte) {
	t.Helper()
	var ackBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/runtime/credential-delivery:claim":
			_ = json.NewEncoder(w).Encode(claimResponse{
				Delivery: &pendingDelivery{
					OperationID: "op-1", RecipientID: "rec-1",
					SecretBackend: "aws-secrets-manager",
					SecretRef:     secretRef,
					SealedPayload: sealed, RecipientKeyID: keyID, IdempotencyKey: "idem-1",
				},
			})
		case "/api/v1/runtime/credential-delivery:ack":
			b, _ := io.ReadAll(r.Body)
			ackBody = b
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "acknowledged"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server, &ackBody
}

func syncConfig(serverURL string, privKey []byte, keyID string) Config {
	return Config{
		ControlPlaneURL: serverURL,
		RuntimeToken:    "tok",
		KeyID:           keyID,
		PrivateKey:      base64.RawStdEncoding.EncodeToString(privKey),
		Timeout:         time.Second,
	}
}

// TestCredentialSyncNeverEmitsPlaintext is the core redaction guarantee: the
// decrypted secret is written to the backend but never appears in the sync
// output or the ack sent back to the control plane.
func TestCredentialSyncNeverEmitsPlaintext(t *testing.T) {
	privKey := newPrivateKey(t)
	const plaintext = "SUPER-SECRET-VALUE-xyz123"
	sealed := sealKMP1(t, plaintext, "runtime-1", "key-1", privKey)
	store := &fakeStore{value: plaintext}
	server, ackBody := newSyncControlPlane(t, "key-1", sealed, "aws-secrets-manager://us-east-1/123456789012/crm-transport")

	out, err := Sync(context.Background(), syncConfig(server.URL, privKey, "key-1"), store, fixedInstallation("runtime-1"))
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if !out.Success {
		t.Fatalf("sync failed: %+v", out)
	}
	if !store.putCalled {
		t.Fatal("backend Put was not called")
	}
	outJSON, _ := json.Marshal(out)
	if strings.Contains(string(outJSON), plaintext) {
		t.Fatalf("sync output leaked plaintext: %s", outJSON)
	}
	if strings.Contains(string(*ackBody), plaintext) {
		t.Fatalf("ack leaked plaintext: %s", *ackBody)
	}
}

// TestCredentialSyncFailureIsRedacted verifies that a leaky backend error (one
// that includes the secret) is replaced by a closed-set failure class and never
// reaches the output.
func TestCredentialSyncFailureIsRedacted(t *testing.T) {
	privKey := newPrivateKey(t)
	const plaintext = "LEAKY-SECRET-VALUE-abc"
	sealed := sealKMP1(t, plaintext, "runtime-1", "key-1", privKey)
	store := &fakeStore{putErr: fmt.Errorf("backend rejected value %s", plaintext)}
	server, _ := newSyncControlPlane(t, "key-1", sealed, "aws-secrets-manager://us-east-1/123456789012/leaky")

	out, err := Sync(context.Background(), syncConfig(server.URL, privKey, "key-1"), store, fixedInstallation("runtime-1"))
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if out.Success {
		t.Fatal("expected sync failure")
	}
	outJSON, _ := json.Marshal(out)
	if strings.Contains(string(outJSON), plaintext) {
		t.Fatalf("failure output leaked plaintext: %s", outJSON)
	}
	if out.Error != "backend_write_error" {
		t.Fatalf("failure reason = %q, want backend_write_error", out.Error)
	}
}

// TestCredentialSyncRejectsInlineMaterialReference verifies the reference gate:
// a delivery whose reference is actually secret material is rejected before any
// backend write, and the untrusted reference is not echoed into the output.
func TestCredentialSyncRejectsInlineMaterialReference(t *testing.T) {
	privKey := newPrivateKey(t)
	sealed := sealKMP1(t, "whatever-the-payload-is", "runtime-1", "key-1", privKey)
	leakyRef := "ghp_" + strings.Repeat("k", 36)
	store := &fakeStore{}
	server, _ := newSyncControlPlane(t, "key-1", sealed, leakyRef)

	out, err := Sync(context.Background(), syncConfig(server.URL, privKey, "key-1"), store, fixedInstallation("runtime-1"))
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if out.Success {
		t.Fatal("expected sync failure for inline-material reference")
	}
	if store.putCalled {
		t.Fatal("backend Put was called for an inline-material reference")
	}
	outJSON, _ := json.Marshal(out)
	if strings.Contains(string(outJSON), leakyRef) {
		t.Fatalf("output echoed the untrusted reference: %s", outJSON)
	}
	if out.Error != string(failureInvalidRef) {
		t.Fatalf("failure reason = %q, want %q", out.Error, failureInvalidRef)
	}
}

// TestCredentialSyncRefusesAnotherRecipientKey: a delivery sealed to a key id
// other than the configured one is acknowledged as a decryption failure and
// never written.
func TestCredentialSyncRefusesAnotherRecipientKey(t *testing.T) {
	privKey := newPrivateKey(t)
	sealed := sealKMP1(t, "value", "runtime-1", "key-1", privKey)
	store := &fakeStore{}
	server, ackBody := newSyncControlPlane(t, "key-1", sealed, "aws-secrets-manager:///x")

	out, err := Sync(context.Background(), syncConfig(server.URL, privKey, "other-key"), store, fixedInstallation("runtime-1"))
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if out.Success || store.putCalled || out.Error != "decryption_error" {
		t.Fatalf("sync = %+v put=%v", out, store.putCalled)
	}
	if !strings.Contains(string(*ackBody), string(failureDecryption)) {
		t.Fatalf("ack = %s", *ackBody)
	}
}

// TestCredentialSyncFailsWhenTheInstallationIsUnknown: without a resolved
// installation nothing is claimed.
func TestCredentialSyncFailsWhenTheInstallationIsUnknown(t *testing.T) {
	claimed := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { claimed = true }))
	t.Cleanup(server.Close)
	unresolved := func(context.Context) (string, error) { return "", errors.New("whoami returned 401") }

	if _, err := Sync(context.Background(), syncConfig(server.URL, newPrivateKey(t), "key-1"), &fakeStore{}, unresolved); err == nil || !strings.Contains(err.Error(), "resolve runtime installation") {
		t.Fatalf("Sync = %v", err)
	}
	if claimed {
		t.Fatal("a delivery was claimed without a resolved installation")
	}
}

// TestFailureReasonWireContract locks the failure-class strings sent to the
// control plane. The first three are the pre-existing wire contract and must
// not change; the last two are additive.
func TestFailureReasonWireContract(t *testing.T) {
	want := map[failureReason]string{
		failureDecryption:      "decryption_failed",
		failureBackendWrite:    "backend_write_failed",
		failureValidation:      "backend_validation_failed",
		failureInvalidRef:      "invalid_secret_ref",
		failureStaleGeneration: "stale_generation",
	}
	seen := map[string]failureReason{}
	for r, wire := range want {
		if string(r) != wire {
			t.Errorf("failureReason %q has wire value %q, want %q", r, string(r), wire)
		}
		if prev, dup := seen[wire]; dup {
			t.Errorf("duplicate wire value %q for %q and %q", wire, prev, r)
		}
		seen[wire] = r
	}
}

func TestIsStaleGeneration(t *testing.T) {
	cases := []struct {
		gen, active int
		want        bool
	}{
		{2, 3, true},
		{3, 3, false},
		{4, 3, false},
		{0, 3, false},
		{2, 0, false},
		{0, 0, false},
	}
	for _, c := range cases {
		if got := isStaleGeneration(c.gen, c.active); got != c.want {
			t.Errorf("isStaleGeneration(%d, %d) = %v, want %v", c.gen, c.active, got, c.want)
		}
	}
}
