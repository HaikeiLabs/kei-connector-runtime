package runtime_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	connectorruntime "github.com/HaikeiLabs/kei-connector-runtime"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/invoke"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/credentials"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/credrelease"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

// HAI-1066: POST /v1/credentials:release for a tool-bound call on a shared
// opaque_ref connector (a postgres DSN, ADR-039) reads the credential from the
// runtime's tenant secret store through the connector reference index, after
// the full authorize decision, and releases it in the same response shape as
// an OAuth release. It never calls the identity service, and neither the
// value nor its secret reference reaches a log line or an audit record.

const (
	pgConnectorID = "00000000-0000-4000-8000-000000001066"
	pgField       = "dsn"
	pgBackend     = "aws-secrets-manager"
	// pgDeliveredRef is where credential sync wrote a Kei-delivered secret.
	pgDeliveredRef = "aws-secrets-manager://us-east-1/kei/connectors/" + pgConnectorID + "/" + pgField
	// pgExternalBareRef is a customer's own secret name (HAI-1000); sync
	// qualifies it for the configured backend.
	pgExternalBareRef = "e2epg/connectors/pg/dsn"
	pgExternalRef     = "aws-secrets-manager:///" + pgExternalBareRef
	pgDSN             = "postgres://ro-user:dsn-canary-1066@db.internal:5432/app?sslmode=require"
	pgResource        = "testenv"
)

type pgSecretStore struct {
	mu     sync.Mutex
	values map[string]string
	reads  int
	// fail and sleep simulate a store outage (HAI-1071).
	fail  bool
	sleep time.Duration
}

func (s *pgSecretStore) Get(ctx context.Context, backend, ref string) (*string, error) {
	s.mu.Lock()
	s.reads++
	v, ok := s.values[backend+"|"+ref]
	fail, sleep := s.fail, s.sleep
	s.mu.Unlock()
	if sleep > 0 {
		select {
		case <-time.After(sleep):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if !ok || fail {
		return nil, errors.New("secret not found")
	}
	return &v, nil
}

func (s *pgSecretStore) readCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

// pgIdentity counts identity-service calls: an opaque_ref release must make
// none for the connector.
type pgIdentity struct {
	mu        sync.Mutex
	connector int
}

func (i *pgIdentity) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case r.URL.Path == credrelease.ResolvePath:
		_ = json.NewEncoder(w).Encode(map[string]any{"credentials": []map[string]string{}})
	case strings.HasPrefix(r.URL.Path, "/api/v1/connectorCredentials/"):
		i.mu.Lock()
		i.connector++
		i.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"connector_id": pgConnectorID, "failure": map[string]any{"reason": "NOT_CONNECTED"}})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// pgBundle is a v2 bundle with a postgres connector descriptor (opaque_ref,
// the given account model) permitted for u-alice through the harness tool
// pg_query. mutate edits the descriptor before encoding; a nil descriptor
// result drops it from the bundle.
func pgBundle(t *testing.T, mutate func(map[string]any) map[string]any) []byte {
	t.Helper()
	policybundle.SetV2SchemaValidator(runtimeV2SchemaValidator(t))
	now := time.Now().UTC()
	descriptor := map[string]any{
		"id": pgConnectorID, "name": "pg-seed", "provider": "postgres", "kind": "database",
		"credential_source": "opaque_ref", "account_model": "shared",
		"credential_ref": "kei://connectors/" + pgConnectorID + "/" + pgField, "credential_backend": pgBackend,
		"capabilities": []any{map[string]any{"name": "query.run", "mutating": false}},
	}
	if mutate != nil {
		descriptor = mutate(descriptor)
	}
	connectors := []any{}
	if descriptor != nil {
		connectors = append(connectors, descriptor)
	}
	raw, err := json.Marshal(map[string]any{
		"schema": "kei.policy-bundle/v2", "bundle_id": "pg-release-bundle", "bundle_version": 1, "policy_revision": 1, "issuer": policybundle.Issuer,
		"audience":  map[string]any{"installation_id": "inst-fixture-0001", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001"},
		"issued_at": now.Format(time.RFC3339Nano), "not_after": now.Add(12 * time.Hour).Format(time.RFC3339Nano),
		"refresh": map[string]any{"poll_interval_seconds": 60, "stale_after_seconds": 300}, "subject_resolution": map[string]any{"mode": "bundle", "max_cache_seconds": 0},
		"policy_set": map[string]any{
			"schema": "kei.policy-set/v2", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "match_semantics": "kei.match/v2",
			"evaluation": map[string]any{"precedence": []string{"priority_desc", "deny_before_permit", "policy_id_asc"}, "checks": "per_capability_first_match_and", "default": "deny"},
			"tools": []any{map[string]any{
				"name": "pg_query", "source": "discord", "operation_class": "read",
				"route": map[string]any{"harness_executor": map[string]any{"executor": "discord", "registration": "pg_query"}},
			}},
			"checks": []any{},
			"tool_policies": []any{map[string]any{
				"policy_id": "pol-pg-permit", "name": "pg-permit", "effect": "permit", "priority": 100,
				"scope":    map[string]any{"org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "agent_id": "agent-fixture-0001"},
				"selector": map[string]any{"source_principal": "user:u-alice", "source": "discord", "tool": "pg_query", "connector_id": pgConnectorID, "capability": "query.run", "resource_id": "*"},
			}},
			"harness_match_semantics": "kei.harness-match/v1", "harness_policies": []any{},
			"connectors": connectors,
		},
		"agent_connector_bindings": []any{map[string]any{"agent_id": "agent-fixture-0001", "connector_id": pgConnectorID, "capabilities": []string{"query.run"}}},
		"identities":               []any{map[string]any{"source": "discord", "external_id": "ext-alice", "user_id": "u-alice", "status": "linked", "subject_token": "es256-subject-alice"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type pgRig struct {
	h        http.Handler
	store    *pgSecretStore
	identity *pgIdentity
	index    string
	mu       sync.Mutex
	audit    []string
	logs     *bytes.Buffer
	pdp      *keiruntime.LocalPDP
	dir      string
}

func (r *pgRig) auditText() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.audit, "\n")
}

type pgRigOptions struct {
	mutate     func(map[string]any) map[string]any
	bundle     []byte // replaces pgBundle when set
	entries    []credentials.ConnectorReference
	noResolver bool
}

func newPGRig(t *testing.T, opts pgRigOptions) *pgRig {
	t.Helper()
	logs := &bytes.Buffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	dir := t.TempDir()
	bundle := opts.bundle
	if bundle == nil {
		bundle = pgBundle(t, opts.mutate)
	}
	activateBundle(t, dir, bundle)
	index := filepath.Join(t.TempDir(), "connector-credentials.json")
	for _, entry := range opts.entries {
		if err := credentials.WriteConnectorReference(index, entry); err != nil {
			t.Fatal(err)
		}
	}
	rig := &pgRig{
		store: &pgSecretStore{values: map[string]string{
			pgBackend + "|" + pgDeliveredRef: pgDSN,
			pgBackend + "|" + pgExternalRef:  pgDSN,
		}},
		identity: &pgIdentity{},
		index:    index,
		logs:     logs,
	}
	srv := httptest.NewServer(rig.identity)
	t.Cleanup(srv.Close)
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken: policyTestToken, RuntimeControlPlaneURL: "https://kei.example", RuntimeStateDir: dir,
	}, func(data json.RawMessage) {
		rig.mu.Lock()
		rig.audit = append(rig.audit, string(data))
		rig.mu.Unlock()
	})
	t.Cleanup(l.Close)
	l.SetIdentity(&keiruntime.Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001"), AgentID: "agent-fixture-0001"})
	l.SetCredentialStore(credrelease.NewStore(credrelease.NewClient(srv.URL, policyTestToken, 5*time.Second)))
	if !opts.noResolver {
		l.SetConnectorSecrets(invoke.SecretResolver{IndexPath: index, Store: rig.store})
	}
	rig.h = sessionHandler(t, l)
	rig.pdp, rig.dir = l, dir
	return rig
}

func deliveredEntry() credentials.ConnectorReference {
	return credentials.ConnectorReference{ConnectorID: pgConnectorID, Field: pgField, SecretBackend: pgBackend, SecretRef: pgDeliveredRef, Generation: 1}
}

func externalEntry() credentials.ConnectorReference {
	return credentials.ConnectorReference{ConnectorID: pgConnectorID, Field: pgField, SecretBackend: pgBackend, SecretRef: pgExternalRef, External: true}
}

type pgReleaseResponse struct {
	Schema     string `json:"schema"`
	Decision   string `json:"decision"`
	ReasonCode string `json:"reason_code"`
	Reason     string `json:"reason"`
	Credential *struct {
		ConnectorID  string `json:"connector_id"`
		AccountModel string `json:"account_model"`
		AccessToken  string `json:"access_token"`
	} `json:"credential"`
}

func (r *pgRig) release(t *testing.T) (pgReleaseResponse, string) {
	t.Helper()
	session := createSession(t, r.h, "ext-alice")
	rec := sessionRequest(r.h, http.MethodPost, "/v1/credentials:release", session,
		fmt.Sprintf(`{"schema":"kei.credential-release-request/v1","tool":"pg_query","connector":{"connector_id":"%s","capability":"query.run"},"resource":"%s"}`, pgConnectorID, pgResource))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var out pgReleaseResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	return out, rec.Body.String()
}

// assertNoLeak checks that neither the value nor any form of its reference
// is in the logs or the audit records.
func (r *pgRig) assertNoLeak(t *testing.T) {
	t.Helper()
	for name, text := range map[string]string{"logs": r.logs.String(), "audit": r.auditText()} {
		for _, needle := range []string{pgDSN, "dsn-canary-1066", "postgres://", pgDeliveredRef, pgExternalRef, pgExternalBareRef, "kei/connectors/" + pgConnectorID} {
			if strings.Contains(text, needle) {
				t.Fatalf("%s contain %q:\n%s", name, needle, text)
			}
		}
	}
}

func TestCredentialsReleaseSharedOpaqueRef(t *testing.T) {
	t.Run("delivered kei ref releases the DSN from the tenant secret store", func(t *testing.T) {
		rig := newPGRig(t, pgRigOptions{entries: []credentials.ConnectorReference{deliveredEntry()}})
		out, _ := rig.release(t)
		if out.Schema != "kei.credential-release-response/v1" || out.Decision != "allow" || out.Credential == nil {
			t.Fatalf("response = %+v, want an allow with a credential", out)
		}
		if out.Credential.AccessToken != pgDSN || out.Credential.ConnectorID != pgConnectorID || out.Credential.AccountModel != "shared" {
			t.Fatalf("credential = connector %q account_model %q value-matches %v", out.Credential.ConnectorID, out.Credential.AccountModel, out.Credential.AccessToken == pgDSN)
		}
		if rig.identity.connector != 0 {
			t.Fatalf("identity service was asked %d times for an opaque_ref connector", rig.identity.connector)
		}
		audit := rig.auditText()
		if !strings.Contains(audit, `"decision":"allow"`) || !strings.Contains(audit, `"credential_kind":"secret_store"`) {
			t.Fatalf("audit = %s, want an allow record with credential_kind secret_store", audit)
		}
		rig.assertNoLeak(t)
	})

	t.Run("external bare ref resolved by credential sync is released through the index", func(t *testing.T) {
		rig := newPGRig(t, pgRigOptions{entries: []credentials.ConnectorReference{externalEntry()}})
		out, _ := rig.release(t)
		if out.Decision != "allow" || out.Credential == nil || out.Credential.AccessToken != pgDSN {
			t.Fatalf("decision/reason = %q/%q, credential present %v, want allow with the DSN", out.Decision, out.ReasonCode, out.Credential != nil)
		}
		rig.assertNoLeak(t)
	})

	denies := map[string]struct {
		opts      pgRigOptions
		reason    string
		readsZero bool
	}{
		"unresolved ref (never delivered)": {opts: pgRigOptions{}, reason: "credential_unavailable"},
		"wrong backend in the index": {opts: pgRigOptions{entries: []credentials.ConnectorReference{{
			ConnectorID: pgConnectorID, Field: pgField, SecretBackend: "azure-key-vault",
			SecretRef: "https://vault.vault.azure.net/secrets/kei-connectors-" + pgConnectorID + "-dsn", Generation: 1,
		}}}, reason: "credential_backend_mismatch", readsZero: true},
		"no descriptor": {opts: pgRigOptions{
			entries: []credentials.ConnectorReference{deliveredEntry()},
			mutate:  func(map[string]any) map[string]any { return nil },
		}, reason: "connector_not_registered", readsZero: true},
		"descriptor without an account model": {opts: pgRigOptions{
			entries: []credentials.ConnectorReference{deliveredEntry()},
			mutate:  func(d map[string]any) map[string]any { delete(d, "account_model"); return d },
		}, reason: "account_model_not_supported", readsZero: true},
		"domain delegation": {opts: pgRigOptions{
			entries: []credentials.ConnectorReference{deliveredEntry()},
			mutate:  func(d map[string]any) map[string]any { d["account_model"] = "domain_delegation"; return d },
		}, reason: "account_model_not_supported", readsZero: true},
		"per_user tenant-stored credential (shared only)": {opts: pgRigOptions{
			entries: []credentials.ConnectorReference{deliveredEntry()},
			mutate:  func(d map[string]any) map[string]any { d["account_model"] = "per_user"; return d },
		}, reason: "account_model_not_supported", readsZero: true},
		"no secret store configured": {opts: pgRigOptions{
			entries: []credentials.ConnectorReference{deliveredEntry()}, noResolver: true,
		}, reason: "credential_unavailable", readsZero: true},
	}
	for name, tc := range denies {
		t.Run("deny: "+name, func(t *testing.T) {
			rig := newPGRig(t, tc.opts)
			out, body := rig.release(t)
			if out.Decision != "deny" || out.Credential != nil || out.ReasonCode != tc.reason {
				t.Fatalf("response = %s, want deny %s with no credential", body, tc.reason)
			}
			if strings.Contains(body, pgDSN) {
				t.Fatal("a deny response carries the DSN")
			}
			if tc.readsZero && rig.store.readCount() != 0 {
				t.Fatalf("secret store read %d times on a deny that needs no read", rig.store.readCount())
			}
			if rig.identity.connector != 0 {
				t.Fatalf("identity service was asked %d times for an opaque_ref connector", rig.identity.connector)
			}
			if !strings.Contains(rig.auditText(), `"reason_code":"`+tc.reason+`"`) {
				t.Fatalf("audit = %s, want a deny record with %s", rig.auditText(), tc.reason)
			}
			rig.assertNoLeak(t)
		})
	}
}
