package connectorruntime

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// sealKMP1 builds a KMP1 envelope for plaintext addressed to runtimeID/keyID,
// using the given 32-byte X25519 private key.
func sealKMP1(t *testing.T, plaintext, runtimeID, keyID string, privKeyBytes []byte) string {
	t.Helper()
	curve := ecdh.X25519()
	privateKey, err := curve.NewPrivateKey(privKeyBytes)
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
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), []byte(runtimeID+"\x00"+keyID))
	payload := append([]byte("KMP1"), ephemeralKey.PublicKey().Bytes()...)
	payload = append(payload, nonce...)
	payload = append(payload, ciphertext...)
	return base64.RawStdEncoding.EncodeToString(payload)
}

// newSyncControlPlane stands up a control plane that serves one delivery for
// the given sealed payload and records the ack body.
func newSyncControlPlane(t *testing.T, runtimeID, keyID, sealed, secretRef string) (*httptest.Server, *[]byte) {
	t.Helper()
	var ackBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/runtime/whoami":
			_ = json.NewEncoder(w).Encode(RuntimeIdentity{ID: runtimeID, OrgID: "org-1", Platform: "slack", Status: "active", BindingStatus: "verified"})
		case "/api/v1/runtime/credential-delivery/claim":
			_ = json.NewEncoder(w).Encode(CredentialDeliveryClaimResponse{
				Delivery: &CredentialDelivery{
					OperationID: "op-1", RecipientID: "rec-1",
					SecretBackend: "aws-secrets-manager",
					SecretRef:     secretRef,
					SealedPayload: sealed, RecipientKeyID: keyID, IdempotencyKey: "idem-1",
				},
			})
		case "/api/v1/runtime/credential-delivery/ack":
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
		RuntimeToken:             "tok",
		RuntimeControlPlaneURL:   serverURL,
		CredentialSyncKeyID:      keyID,
		CredentialSyncPrivateKey: base64.RawStdEncoding.EncodeToString(privKey),
	}
}

// TestCredentialSyncNeverEmitsPlaintext is the core redaction guarantee: the
// decrypted secret is written to the backend but never appears in the sync
// output or the ack sent back to the control plane.
func TestCredentialSyncNeverEmitsPlaintext(t *testing.T) {
	privKey := make([]byte, 32)
	if _, err := rand.Read(privKey); err != nil {
		t.Fatal(err)
	}
	const (
		plaintext = "SUPER-SECRET-VALUE-xyz123"
		runtimeID = "runtime-1"
		keyID     = "key-1"
	)
	sealed := sealKMP1(t, plaintext, runtimeID, keyID, privKey)
	store := &fakeBackend{value: plaintext}
	server, ackBody := newSyncControlPlane(t, runtimeID, keyID, sealed, "aws-secrets-manager://us-east-1/123456789012/crm-transport")

	out, err := performCredentialSync(context.Background(), syncConfig(server.URL, privKey, keyID), time.Second, store)
	if err != nil {
		t.Fatalf("performCredentialSync: %v", err)
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
	privKey := make([]byte, 32)
	if _, err := rand.Read(privKey); err != nil {
		t.Fatal(err)
	}
	const (
		plaintext = "LEAKY-SECRET-VALUE-abc"
		runtimeID = "runtime-1"
		keyID     = "key-1"
	)
	sealed := sealKMP1(t, plaintext, runtimeID, keyID, privKey)
	store := &fakeBackend{putErr: fmt.Errorf("backend rejected value %s", plaintext)}
	server, _ := newSyncControlPlane(t, runtimeID, keyID, sealed, "aws-secrets-manager://us-east-1/123456789012/leaky")

	out, err := performCredentialSync(context.Background(), syncConfig(server.URL, privKey, keyID), time.Second, store)
	if err != nil {
		t.Fatalf("performCredentialSync: %v", err)
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
	privKey := make([]byte, 32)
	if _, err := rand.Read(privKey); err != nil {
		t.Fatal(err)
	}
	const (
		plaintext = "whatever-the-payload-is"
		runtimeID = "runtime-1"
		keyID     = "key-1"
	)
	sealed := sealKMP1(t, plaintext, runtimeID, keyID, privKey)
	leakyRef := "ghp_" + strings.Repeat("k", 36)
	store := &fakeBackend{}
	server, _ := newSyncControlPlane(t, runtimeID, keyID, sealed, leakyRef)

	out, err := performCredentialSync(context.Background(), syncConfig(server.URL, privKey, keyID), time.Second, store)
	if err != nil {
		t.Fatalf("performCredentialSync: %v", err)
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
	if out.Error != string(FailureInvalidRef) {
		t.Fatalf("failure reason = %q, want %q", out.Error, FailureInvalidRef)
	}
}

// TestAuthorizeAuditEventNeverCarriesCredential is the transport redaction
// guarantee: the audit record emitted for an allow decision never includes the
// served credential, even though the output carries it for the agent.
func TestAuthorizeAuditEventNeverCarriesCredential(t *testing.T) {
	const secret = "crm-transport-key-SECRET"
	p := authorizeParams{
		user: "u-1", tool: "crm", agentID: "a-1", framework: "test",
		invokingSubject: "u-1", resources: []string{"crm:repo:leads"},
	}
	resp := &AuthorizeResponse{Decision: "allow", PolicyID: "pol-1", OrgID: strPtr("org-1")}
	out := AuthorizeOutput{Decision: "allow", Service: "crm", Credential: &CredentialResponse{Value: secret}}
	event := buildDecisionEvent(p, resp, out, "crm:repo:leads")
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatalf("audit event leaked the credential: %s", data)
	}
}

func strPtr(s string) *string { return &s }

// TestFailureReasonWireContract locks the failure-class strings sent to the
// control plane. The first three are the pre-existing wire contract and must
// not change; the last two are additive.
func TestFailureReasonWireContract(t *testing.T) {
	want := map[FailureReason]string{
		FailureDecryption:      "decryption_failed",
		FailureBackendWrite:    "backend_write_failed",
		FailureValidation:      "backend_validation_failed",
		FailureInvalidRef:      "invalid_secret_ref",
		FailureStaleGeneration: "stale_generation",
	}
	seen := map[string]FailureReason{}
	for r, wire := range want {
		if string(r) != wire {
			t.Errorf("FailureReason %q has wire value %q, want %q", r, string(r), wire)
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
