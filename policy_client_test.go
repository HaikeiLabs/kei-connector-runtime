package connectorruntime

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

func TestSyncPolicyBundlePinsAuthenticatedKeysAndActivatesVerifiedBundle(t *testing.T) {
	now := time.Now().UTC()
	envelope, keys := signedExampleBundle(t, now)
	var e policybundle.Envelope
	if err := json.Unmarshal(envelope, &e); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	etag := fmt.Sprintf(`"sha256:%x"`, digest)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer kh_live_runtime_test_token_1234567890" {
			t.Errorf("authorization header missing")
		}
		switch r.URL.Path {
		case "/api/v1/runtime/policy-signing-keys":
			w.Header().Set("ETag", "keys-etag")
			_ = json.NewEncoder(w).Encode(keys)
		case "/api/v1/runtime/policy-bundles/current":
			if r.Header.Get("Accept") != policybundle.PayloadType {
				t.Errorf("Accept=%q", r.Header.Get("Accept"))
			}
			w.Header().Set("ETag", etag)
			w.Header().Set("Kei-Policy-Keys-ETag", "keys-etag")
			w.Header().Set("Kei-Policy-Bundle-Version", "42")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write(envelope)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	stateDir := t.TempDir()
	cfg := Config{RuntimeToken: "kh_live_runtime_test_token_1234567890", RuntimeControlPlaneURL: server.URL, RuntimeStateDir: stateDir}
	identity := &RuntimeIdentity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001"), Status: "active", BindingStatus: "verified"}
	if err := syncPolicyBundle(context.Background(), cfg, identity, time.Second); err != nil {
		t.Fatal(err)
	}
	store, err := policybundle.OpenStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	bundle, state, err := store.Check(identity.ID, identity.OrgID, *identity.WorkspaceID, time.Now().UTC(), false)
	if err != nil {
		t.Fatal(err)
	}
	if bundle == nil || state != policybundle.Active || bundle.Payload.BundleVersion != 42 {
		t.Fatalf("bundle=%v state=%s", bundle, state)
	}
}

func TestPolicyBundleEndpointRevocationDeletesPersistedEnforcementState(t *testing.T) {
	now := time.Now().UTC()
	stateDir := t.TempDir()
	_, store := mustActivateTestBundle(t, stateDir, now)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/runtime/policy-signing-keys" {
			http.Error(w, "revoked", http.StatusForbidden)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	cfg := Config{RuntimeToken: "kh_live_runtime_test_token_1234567890", RuntimeControlPlaneURL: server.URL, RuntimeStateDir: stateDir}
	identity := &RuntimeIdentity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001")}
	if err := syncPolicyBundle(context.Background(), cfg, identity, time.Second); err == nil {
		t.Fatal("expected revoked control-plane request to fail")
	}
	_, state, err := store.Check(identity.ID, identity.OrgID, *identity.WorkspaceID, time.Now().UTC(), false)
	if err == nil || state != policybundle.Revoked {
		t.Fatalf("after revocation state=%s err=%v", state, err)
	}
}
