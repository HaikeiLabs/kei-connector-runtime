package connectorruntime

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newDeliveryControlPlane serves one delivery and records the ack.
func newDeliveryControlPlane(t *testing.T, runtimeID string, delivery CredentialDelivery) (*httptest.Server, *CredentialDeliveryAckRequest) {
	t.Helper()
	var ack CredentialDeliveryAckRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/runtime/whoami":
			_ = json.NewEncoder(w).Encode(RuntimeIdentity{ID: runtimeID, OrgID: "org-1", Platform: "discord", Status: "active", BindingStatus: "verified"})
		case "/api/v1/runtime/credential-delivery/claim":
			_ = json.NewEncoder(w).Encode(CredentialDeliveryClaimResponse{Delivery: &delivery})
		case "/api/v1/runtime/credential-delivery/ack":
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &ack)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "acknowledged"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server, &ack
}

const syncConnectorID = "7d1c9a52-6f0e-4d1b-9a53-0f2f6f0f1a11"

func connectorDelivery(t *testing.T, plaintext, runtimeID, keyID, secretRef string, privKey []byte) CredentialDelivery {
	return CredentialDelivery{
		OperationID: "op-1", RecipientID: "rec-1", GenerationID: "gen-1", Generation: 2,
		SecretBackend: "aws-secrets-manager", SecretRef: secretRef,
		SealedPayload: sealKMP1(t, plaintext, runtimeID, keyID, privKey), RecipientKeyID: keyID, IdempotencyKey: "gen-1",
		OperationKind: OperationKindConnectorSecret, ConnectorID: syncConnectorID, Field: "api_token",
	}
}

// TestCredentialSyncWritesAConnectorSecret: a connector_secret delivery takes
// the model-profile path unchanged — decrypt, write the backend reference,
// validate, ack — and the output names the connector field, never the value.
func TestCredentialSyncWritesAConnectorSecret(t *testing.T) {
	privKey := make([]byte, 32)
	if _, err := rand.Read(privKey); err != nil {
		t.Fatal(err)
	}
	const plaintext = "FAKE-TITO-TOKEN-FOR-SYNC-TEST-0001"
	ref := "aws-secrets-manager://us-west-2/kei/acme/connectors/" + syncConnectorID + "/api_token"
	server, ack := newDeliveryControlPlane(t, "runtime-1", connectorDelivery(t, plaintext, "runtime-1", "key-1", ref, privKey))
	store := &fakeBackend{value: plaintext}

	out, err := performCredentialSync(context.Background(), syncConfig(server.URL, privKey, "key-1"), time.Second, store)
	if err != nil {
		t.Fatalf("performCredentialSync: %v", err)
	}
	if !out.Success || !store.putCalled || store.lastRef != ref {
		t.Fatalf("sync = %+v, put=%v ref=%q", out, store.putCalled, store.lastRef)
	}
	if out.OperationKind != OperationKindConnectorSecret || out.ConnectorID != syncConnectorID || out.Field != "api_token" {
		t.Fatalf("output does not name the connector field: %+v", out)
	}
	if !ack.Success || ack.OperationID != "op-1" || ack.RecipientID != "rec-1" {
		t.Fatalf("ack = %+v", ack)
	}
	raw, _ := json.Marshal(out)
	ackRaw, _ := json.Marshal(ack)
	if strings.Contains(string(raw), plaintext) || strings.Contains(string(ackRaw), plaintext) {
		t.Fatal("connector secret leaked into the output or ack")
	}
}

// TestCredentialSyncRefusesAConnectorSecretForAnotherLocation: a connector
// delivery may only write the location named for that connector field, so a
// wrong reference (for example a model profile's) is never overwritten.
func TestCredentialSyncRefusesAConnectorSecretForAnotherLocation(t *testing.T) {
	privKey := make([]byte, 32)
	if _, err := rand.Read(privKey); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{
		"aws-secrets-manager://us-west-2/kei/acme/9b0f3f1e-8a5e-4a57-9d8a-2a9f0c7b1e22",
		"aws-secrets-manager://us-west-2/kei/acme/connectors/" + syncConnectorID + "/other_field",
		"aws-secrets-manager://us-west-2/kei/acme/connectors/00000000-0000-0000-0000-000000000000/api_token",
	} {
		server, ack := newDeliveryControlPlane(t, "runtime-1", connectorDelivery(t, "FAKE-VALUE-0002", "runtime-1", "key-1", ref, privKey))
		store := &fakeBackend{}
		out, err := performCredentialSync(context.Background(), syncConfig(server.URL, privKey, "key-1"), time.Second, store)
		if err != nil {
			t.Fatalf("performCredentialSync: %v", err)
		}
		if out.Success || store.putCalled || out.Error != string(FailureInvalidRef) {
			t.Fatalf("%s: sync = %+v put=%v", ref, out, store.putCalled)
		}
		if ack.Success || ack.FailureReason != string(FailureInvalidRef) {
			t.Fatalf("%s: ack = %+v", ref, ack)
		}
	}
}

func TestConnectorSecretRefNamesTheField(t *testing.T) {
	for ref, want := range map[string]bool{
		"aws-secrets-manager://us-west-2/kei/acme/connectors/" + syncConnectorID + "/api_token":         true,
		"https://acme.vault.azure.net/secrets/kei-acme-connectors-" + syncConnectorID + "-api-token":    true,
		"projects/acme/secrets/kei-acme-connectors-" + syncConnectorID + "-api_token":                   true,
		"aws-secrets-manager://us-west-2/kei/acme/connectors/" + syncConnectorID + "/api_token/extra":   false,
		"https://acme.vault.azure.net/secrets/kei-acme-connectors-" + syncConnectorID + "-api-token/v2": false,
		"aws-secrets-manager://us-west-2/kei/acme/" + syncConnectorID:                                   false,
	} {
		if got := connectorSecretRefNamesField(ref, syncConnectorID, "api_token"); got != want {
			t.Errorf("connectorSecretRefNamesField(%q) = %v, want %v", ref, got, want)
		}
	}
	if connectorSecretRefNamesField("aws-secrets-manager://r/kei/connectors/../api_token", "..", "api_token") {
		t.Error("a non-id connector_id was accepted")
	}
}
