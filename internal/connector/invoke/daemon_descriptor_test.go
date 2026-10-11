package invoke

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	runtimecredentials "github.com/HaikeiLabs/kei-connector-runtime/internal/credentials"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

// HAI-378 (ADR-034 amendment 2026-10-11): the serve daemon runs opaque_ref
// connectors from the bundle's non-secret descriptors. The credential is
// resolved through the connector reference index and the tenant secret store
// inside the daemon, and reaches only the outbound provider request.

const (
	descriptorSentinel  = "kei-sentinel-crm-api-key-7f3a9c2e"
	descriptorBackend   = "aws-secrets-manager"
	descriptorSecretRef = "aws-secrets-manager://us-west-2/kei/acme/connectors/" + execConnector + "/api_key"
	descriptorCRMHost   = "crm.example.com"
)

// sentinelStore is a fake tenant secret store holding the sentinel.
type sentinelStore struct {
	mu     sync.Mutex
	values map[string]string
	err    error
	block  bool
	calls  int
}

func (s *sentinelStore) Get(ctx context.Context, backend, ref string) (*string, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	if s.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if s.err != nil {
		return nil, s.err
	}
	v, ok := s.values[backend+"|"+ref]
	if !ok {
		return nil, errors.New("secret not found")
	}
	return &v, nil
}

func crmDescriptor() *policybundle.Connector {
	return &policybundle.Connector{
		ID: execConnector, Name: "crm", Provider: "http_api",
		Capabilities:     []policybundle.ConnectorCapability{{Name: "http.get"}},
		CredentialSource: "opaque_ref", AccountModel: "shared",
		CredentialRef: "kei://connectors/" + execConnector + "/api_key", CredentialBackend: descriptorBackend,
		HTTPAPI: &contract.HTTPAPI{
			RegisteredBaseURL: "https://" + descriptorCRMHost + "/api", RegisteredHostname: descriptorCRMHost,
			AllowedMethods: []contract.HTTPMethod{contract.HTTPMethodGet}, AllowedPathPatterns: []string{"/leads/*"},
			QueryAllowlist: []string{"limit"}, RequestMaxBytes: 1024, ResponseMaxBytes: 65536, TimeoutMS: 5000,
			CredentialInjection: contract.CredentialInjection{Location: contract.CredentialInjectionHeader, Name: "Authorization", Scheme: "Bearer"},
			Redaction:           contract.RedactionRules{Headers: []string{"Authorization"}, QueryParameters: []string{}, ResponseFields: []string{"email"}},
		},
	}
}

// descriptorRig is a daemon whose bundle carries descriptors, a connector
// reference index written the way `kei-proxy credential sync` writes it, a
// fake secret store, and a fake CRM behind a real TLS httptest server.
type descriptorRig struct {
	t         *testing.T
	daemon    *Daemon
	grant     Grant
	store     *sentinelStore
	indexPath string
	audit     []string
	logs      bytes.Buffer

	mu          sync.Mutex
	crmRequests []*http.Request
	crmAuth     []string
}

func newDescriptorRig(t *testing.T) *descriptorRig {
	t.Helper()
	rig := &descriptorRig{t: t, store: &sentinelStore{values: map[string]string{descriptorBackend + "|" + descriptorSecretRef: descriptorSentinel}}}
	prevLog := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&rig.logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prevLog) })

	crm := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rig.mu.Lock()
		rig.crmRequests = append(rig.crmRequests, r)
		rig.crmAuth = append(rig.crmAuth, r.Header.Get("Authorization"))
		rig.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Host != descriptorCRMHost:
			w.WriteHeader(http.StatusMisdirectedRequest)
		case r.URL.Path == "/api/leads/42":
			_, _ = io.WriteString(w, `{"id":42,"name":"Ada","email":"ada@example.test"}`)
		case r.URL.Path == "/api/leads/echo":
			// A hostile provider echoes the credential back in its body.
			_, _ = io.WriteString(w, `{"id":1,"echo":"`+r.Header.Get("Authorization")+`"}`)
		case r.URL.Path == "/api/leads/revoked":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"bad key `+r.Header.Get("Authorization")+`"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(crm.Close)
	tlsConfig := crm.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tlsConfig.ServerName = "example.com"
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, crm.Listener.Addr().String())
		},
	}
	t.Cleanup(transport.CloseIdleConnections)

	dir := filepath.Join(t.TempDir(), "state")
	rig.indexPath = runtimecredentials.ConnectorIndexPath(dir)
	rig.writeIndex(runtimecredentials.ConnectorReference{ConnectorID: execConnector, Field: "api_key", SecretBackend: descriptorBackend, SecretRef: descriptorSecretRef, Generation: 1})

	rig.grant = Grant{Allow: true, HasSession: true, Subject: execUser, Provider: "http_api", ConnectorID: execConnector, Capabilities: []string{"http.get"}, TenantID: execTenant, WorkspaceID: execWorkspace, Connector: crmDescriptor(), Descriptors: true}
	rig.daemon = &Daemon{
		Env: Env{
			ProviderTransport: transport,
			LookupIP:          func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("93.184.216.34")}, nil },
			Audit: func(record []byte) error {
				rig.audit = append(rig.audit, string(record))
				return nil
			},
		},
		Authorize: func(context.Context, DaemonCall) (Grant, error) { return rig.grant, nil },
		UseCredential: func(context.Context, string, string, string, func(string) error) error {
			t.Error("an opaque_ref descriptor must not use the session credential store")
			return errors.New("unexpected session credential")
		},
		Secrets: SecretResolver{IndexPath: rig.indexPath, Store: rig.store},
	}
	return rig
}

func (rig *descriptorRig) writeIndex(entry runtimecredentials.ConnectorReference) {
	rig.t.Helper()
	if err := runtimecredentials.WriteConnectorReference(rig.indexPath, entry); err != nil {
		rig.t.Fatal(err)
	}
}

// writeRawIndex writes an index entry WriteConnectorReference would refuse,
// as a tampered or stale index could hold.
func (rig *descriptorRig) writeRawIndex(entry runtimecredentials.ConnectorReference) {
	rig.t.Helper()
	raw, err := json.Marshal(map[string]any{"version": 1, "entries": map[string]any{entry.ConnectorID + "/" + entry.Field: entry}})
	if err != nil {
		rig.t.Fatal(err)
	}
	if err := os.WriteFile(rig.indexPath, raw, 0o600); err != nil {
		rig.t.Fatal(err)
	}
}

func (rig *descriptorRig) invoke(capability, action, resource, input string) (daemonResponse, string) {
	rig.t.Helper()
	body, _ := json.Marshal(daemonRequest{Schema: daemonRequestSchema, ConnectorID: execConnector, Capability: capability, Action: action, Resource: resource, Input: json.RawMessage(input), TraceID: "trace-hai-378", AgentID: execAgent})
	rec := httptest.NewRecorder()
	rig.daemon.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, DaemonInvokePath, bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		rig.t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out daemonResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		rig.t.Fatal(err)
	}
	return out, rec.Body.String()
}

// assertNoLeak fails if the sentinel reached anything but the provider.
func (rig *descriptorRig) assertNoLeak(socketBody string) {
	rig.t.Helper()
	for name, text := range map[string]string{"socket response": socketBody, "audit": strings.Join(rig.audit, "\n"), "log": rig.logs.String()} {
		if strings.Contains(text, descriptorSentinel) || strings.Contains(text, descriptorSecretRef) {
			rig.t.Fatalf("%s leaked the credential or its location:\n%s", name, text)
		}
	}
}

func TestDaemonDescriptorHTTPAPICRMRoundTrip(t *testing.T) {
	rig := newDescriptorRig(t)
	out, body := rig.invoke("http.get", "read", "/leads/42", `{"path":"/leads/42","query":{"limit":["5"]}}`)
	if out.Decision != "allow" || out.Provider != "http_api" {
		t.Fatalf("outcome = %s %s %s", out.Decision, out.ReasonCode, body)
	}
	rig.mu.Lock()
	requests, auth := rig.crmRequests, rig.crmAuth
	rig.mu.Unlock()
	if len(requests) != 1 || requests[0].URL.Query().Get("limit") != "5" {
		t.Fatalf("CRM requests = %d", len(requests))
	}
	// The sentinel is on the outbound request, in the descriptor's header.
	if auth[0] != "Bearer "+descriptorSentinel {
		t.Fatal("the CRM request did not carry the resolved credential in the descriptor's injection header")
	}
	var result struct {
		StatusCode int            `json:"status_code"`
		Body       map[string]any `json:"body"`
	}
	if err := json.Unmarshal(out.Result, &result); err != nil || result.StatusCode != http.StatusOK || result.Body["name"] != "Ada" || strings.Contains(string(out.Result), "ada@example.test") {
		t.Fatalf("result = %s (%v)", out.Result, err)
	}
	rig.assertNoLeak(body)
	if len(rig.audit) != 1 || !strings.Contains(rig.audit[0], `"credential_source":"opaque_ref"`) {
		t.Fatalf("audit = %v", rig.audit)
	}
}

// Every ADR-034 failure mode denies before the provider is called and leaks
// nothing (HAI-378 amendment, "Failure modes (all fail closed)").
func TestDaemonDescriptorDenyMatrix(t *testing.T) {
	type tc struct {
		mutate     func(rig *descriptorRig)
		capability string
		want       string
	}
	cases := map[string]tc{
		"bundle without descriptors runs no opaque_ref connector": {mutate: func(r *descriptorRig) { r.grant.Descriptors, r.grant.Connector = false, nil }, want: "credential_source_not_supported"},
		"connector routed but no descriptor":                      {mutate: func(r *descriptorRig) { r.grant.Connector = nil }, want: "descriptor_invalid"},
		"descriptor names another connector":                      {mutate: func(r *descriptorRig) { r.grant.Connector.ID = "77777777-7777-7777-7777-777777777777" }, want: "descriptor_invalid"},
		"descriptor fails the http_api contract":                  {mutate: func(r *descriptorRig) { r.grant.Connector.HTTPAPI.RegisteredBaseURL = "http://" + descriptorCRMHost }, want: "descriptor_invalid"},
		"descriptor method this contracts version lacks": {mutate: func(r *descriptorRig) {
			r.grant.Connector.HTTPAPI.AllowedMethods = append(r.grant.Connector.HTTPAPI.AllowedMethods, "POST")
		}, want: "descriptor_invalid"},
		"capability this contracts version lacks": {mutate: func(r *descriptorRig) {
			r.grant.Connector.Capabilities = append(r.grant.Connector.Capabilities, policybundle.ConnectorCapability{Name: "http.post", Mutating: true})
		}, capability: "http.post", want: "descriptor_invalid"},
		"capability not on the descriptor": {mutate: func(r *descriptorRig) {
			r.grant.Connector.Capabilities = []policybundle.ConnectorCapability{{Name: "http.head"}}
		}, want: "descriptor_invalid"},
		"domain_delegation":         {mutate: func(r *descriptorRig) { r.grant.Connector.AccountModel = "domain_delegation" }, want: "account_model_not_supported"},
		"shared oauth":              {mutate: func(r *descriptorRig) { r.grant.Connector.CredentialSource = "oauth" }, want: "credential_source_not_supported"},
		"unknown credential source": {mutate: func(r *descriptorRig) { r.grant.Connector.CredentialSource = "vault" }, want: "descriptor_invalid"},
		"credential_ref names another connector": {mutate: func(r *descriptorRig) {
			r.grant.Connector.CredentialRef = "kei://connectors/77777777-7777-7777-7777-777777777777/api_key"
		}, want: "descriptor_invalid"},
		"credential_ref is not a kei reference": {mutate: func(r *descriptorRig) { r.grant.Connector.CredentialRef = descriptorSecretRef }, want: "descriptor_invalid"},
		"secret never delivered":                {mutate: func(r *descriptorRig) { _ = os.Remove(r.indexPath) }, want: "credential_unavailable"},
		"secret delivered for another field": {mutate: func(r *descriptorRig) {
			r.grant.Connector.CredentialRef = "kei://connectors/" + execConnector + "/api_token"
		}, want: "credential_unavailable"},
		"index backend differs": {mutate: func(r *descriptorRig) {
			r.writeIndex(runtimecredentials.ConnectorReference{ConnectorID: execConnector, Field: "api_key", SecretBackend: "azure-key-vault", SecretRef: "https://acme.vault.azure.net/secrets/kei-connectors-" + execConnector + "-api-key", Generation: 2})
		}, want: "credential_backend_mismatch"},
		"index reference names another connector": {mutate: func(r *descriptorRig) {
			r.writeRawIndex(runtimecredentials.ConnectorReference{ConnectorID: execConnector, Field: "api_key", SecretBackend: descriptorBackend, SecretRef: "aws-secrets-manager://us-west-2/kei/acme/connectors/77777777-7777-7777-7777-777777777777/api_key", Generation: 2})
		}, want: "credential_backend_mismatch"},
		"index reference names another field": {mutate: func(r *descriptorRig) {
			r.writeRawIndex(runtimecredentials.ConnectorReference{ConnectorID: execConnector, Field: "api_key", SecretBackend: descriptorBackend, SecretRef: "aws-secrets-manager://us-west-2/kei/acme/connectors/" + execConnector + "/other_key", Generation: 2})
		}, want: "credential_backend_mismatch"},
		"backend the runtime cannot read": {mutate: func(r *descriptorRig) {
			r.grant.Connector.CredentialBackend = "vault"
			r.writeIndex(runtimecredentials.ConnectorReference{ConnectorID: execConnector, Field: "api_key", SecretBackend: "vault", SecretRef: "kv/kei/connectors/" + execConnector + "/api_key", Generation: 2})
			r.store.err = errors.New("secret store unavailable")
		}, want: "credential_unavailable"},
		"secret store read fails": {mutate: func(r *descriptorRig) { r.store.err = errors.New("AccessDenied: " + descriptorSentinel) }, want: "credential_unavailable"},
		"secret store times out": {mutate: func(r *descriptorRig) {
			r.store.block = true
			r.daemon.Secrets.Timeout = 1
		}, want: "credential_unavailable"},
		"empty secret":    {mutate: func(r *descriptorRig) { r.store.values[descriptorBackend+"|"+descriptorSecretRef] = "" }, want: "credential_unavailable"},
		"no secret store": {mutate: func(r *descriptorRig) { r.daemon.Secrets.Store = nil }, want: "credential_unavailable"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			rig := newDescriptorRig(t)
			c.mutate(rig)
			capability, action := "http.get", "read"
			if c.capability == "http.post" {
				capability, action = "http.post", "create"
			}
			out, body := rig.invoke(capability, action, "/leads/42", `{"path":"/leads/42"}`)
			if out.Decision != "deny" || out.ReasonCode != c.want || out.Result != nil {
				t.Fatalf("outcome = %s %s, want deny %s: %s", out.Decision, out.ReasonCode, c.want, body)
			}
			rig.mu.Lock()
			calls := len(rig.crmRequests)
			rig.mu.Unlock()
			if calls != 0 {
				t.Fatalf("the provider was called %d times on a deny", calls)
			}
			rig.assertNoLeak(body)
		})
	}
}

// A provider that echoes the resolved secret back cannot carry it out of the
// daemon in the result.
func TestDaemonDescriptorProviderEchoDenies(t *testing.T) {
	rig := newDescriptorRig(t)
	out, body := rig.invoke("http.get", "read", "/leads/echo", `{"path":"/leads/echo"}`)
	if out.Decision != "deny" || out.ReasonCode != "provider_error" || out.Result != nil {
		t.Fatalf("outcome = %s %s: %s", out.Decision, out.ReasonCode, body)
	}
	rig.assertNoLeak(body)
}

// A provider that rejects the resolved secret gets one request; the secret
// is not re-fetched or tried against another backend.
func TestDaemonDescriptorProvider401IsNotRefetched(t *testing.T) {
	rig := newDescriptorRig(t)
	_, body := rig.invoke("http.get", "read", "/leads/revoked", `{"path":"/leads/revoked"}`)
	rig.mu.Lock()
	calls := len(rig.crmRequests)
	rig.mu.Unlock()
	if calls != 1 || rig.store.calls != 1 {
		t.Fatalf("CRM requests %d, store reads %d, want 1 and 1: %s", calls, rig.store.calls, body)
	}
	rig.assertNoLeak(body)
}

// With descriptors, a per_user oauth connector keeps the session path.
func TestDaemonDescriptorPerUserOAuthUsesTheSessionCredential(t *testing.T) {
	rig := newDescriptorRig(t)
	rig.grant.Provider, rig.grant.Capabilities = "github", []string{"repository.read"}
	rig.grant.Connector = &policybundle.Connector{ID: execConnector, Provider: "github", Capabilities: []policybundle.ConnectorCapability{{Name: "repository.read"}}, CredentialSource: "oauth", AccountModel: "per_user"}
	var used string
	rig.daemon.UseCredential = func(_ context.Context, _, subject, provider string, fn func(string) error) error {
		used = subject + "/" + provider
		return fn("fake-github-session-token")
	}
	rig.daemon.Env.ProviderTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"name":"kei","owner":{"login":"acme"},"description":"","default_branch":"main","private":true}`)), Request: req}, nil
	})
	out, body := rig.invoke("repository.read", "read", "repos/acme/kei", `{}`)
	if out.Decision != "allow" || used != execUser+"/github" || rig.store.calls != 0 {
		t.Fatalf("outcome = %s %s, credential %q, store calls %d: %s", out.Decision, out.ReasonCode, used, rig.store.calls, body)
	}
}

func TestIsSessionProviderComesFromTheContractSetupSchemas(t *testing.T) {
	for provider, want := range map[string]bool{"github": true, "linear": true, "gmail": true, "google_drive": true, "notion": false, "http_api": false, "tito": false, "discord": false, "grafana": false, "crm": false, "unknown": false} {
		if got := IsSessionProvider(provider); got != want {
			t.Errorf("IsSessionProvider(%q) = %v, want %v", provider, got, want)
		}
	}
}
