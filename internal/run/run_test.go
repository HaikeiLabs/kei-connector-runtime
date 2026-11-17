package run

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/invoke"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/credentials"
)

type testRunResolver struct {
	value, link string
	err         error
}

type fakeRunAuthorization struct {
	response    *invoke.Response
	err         error
	gotResource string
}

func (a *fakeRunAuthorization) Authorize(_ context.Context, _, _, resource string) (*invoke.Response, error) {
	a.gotResource = resource
	return a.response, a.err
}

type fakeRunSecretStore struct {
	value *string
	err   error
	reads int
}

func (s *fakeRunSecretStore) Get(context.Context, string, string) (*string, error) {
	s.reads++
	return s.value, s.err
}
func (*fakeRunSecretStore) Put(context.Context, string, string, string) error { return nil }
func (*fakeRunSecretStore) Delete(context.Context, string, string) error      { return nil }
func (*fakeRunSecretStore) Validate(context.Context, string, string) error    { return nil }

func TestDeliveredRunResolverAuthorizesThenReadsFakeBackend(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000000123"
	secretRef := "aws-secrets-manager://region/connectors/" + id + "/api_token"
	index := filepath.Join(t.TempDir(), "connector-credentials.json")
	if err := credentials.WriteConnectorReference(index, credentials.ConnectorReference{ConnectorID: id, Field: "api_token", SecretBackend: "aws-secrets-manager", SecretRef: secretRef, Generation: 1}); err != nil {
		t.Fatal(err)
	}
	value := "fake-secret-value"
	store := &fakeRunSecretStore{value: &value}
	auth := &fakeRunAuthorization{response: &invoke.Response{Decision: "allow", Connector: &invoke.Descriptor{Metadata: contract.Metadata{ID: id, CredentialRef: "api_token"}, CredentialBackend: "aws-secrets-manager", CredentialSecretRef: secretRef}}}
	resolver := deliveredRunResolver{cfg: Config{RuntimeStateDir: filepath.Dir(index)}, store: store, authorization: auth}
	got, _, err := resolver.Resolve(context.Background(), id, "api_token")
	if err != nil || got != value || store.reads != 1 || auth.gotResource != "kei://connectors/"+id+"/api_token" {
		t.Fatalf("resolve=%q err=%v reads=%d resource=%q", got, err, store.reads, auth.gotResource)
	}
}

func TestDeliveredRunResolverFailsClosedForDenyAndMissing(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000000123"
	for _, tc := range []struct {
		name, decision, source, reason string
		indexed                        bool
	}{
		{name: "deny", decision: "deny", reason: "policy_denied", indexed: true},
		{name: "unresolved", decision: "allow", source: "opaque_ref", reason: "unresolved_reference"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			ref := "aws-secrets-manager://region/connectors/" + id + "/api_token"
			if tc.indexed {
				if err := credentials.WriteConnectorReference(filepath.Join(dir, "connector-credentials.json"), credentials.ConnectorReference{ConnectorID: id, Field: "api_token", SecretBackend: "aws-secrets-manager", SecretRef: ref, Generation: 1}); err != nil {
					t.Fatal(err)
				}
			}
			store := &fakeRunSecretStore{value: ptr("secret")}
			auth := &fakeRunAuthorization{response: &invoke.Response{Decision: tc.decision, Connector: &invoke.Descriptor{Metadata: contract.Metadata{ID: id, CredentialRef: "api_token", CredentialSource: contract.CredentialSource(tc.source)}, CredentialBackend: "aws-secrets-manager", CredentialSecretRef: ref}}}
			_, _, err := (deliveredRunResolver{cfg: Config{RuntimeStateDir: dir}, store: store, authorization: auth}).Resolve(context.Background(), id, "api_token")
			var reason runReasonError
			if !errors.As(err, &reason) || reason.reason != tc.reason {
				t.Fatalf("error=%v want reason %s", err, tc.reason)
			}
			if tc.reason != "unresolved_reference" && store.reads != 0 {
				t.Fatalf("unauthorized/unsupported flow read backend %d times", store.reads)
			}
		})
	}
}
func ptr(v string) *string { return &v }

type fakeRunCredentialBinding struct {
	backend, ref, connectURL string
	err                      error
}

type fakeSubjectSource struct {
	userID string
	err    error
}

func (f *fakeSubjectSource) Subject(_ context.Context) (string, error) {
	return f.userID, f.err
}

func (f *fakeRunCredentialBinding) Resolve(_ context.Context, _, _, _ string) (string, string, string, error) {
	return f.backend, f.ref, f.connectURL, f.err
}

func (r testRunResolver) Resolve(context.Context, string, string) (string, string, error) {
	return r.value, r.link, r.err
}

func TestRunInjectsChildOnlyMasksAndAuditsWithoutCredential(t *testing.T) {
	const secret = "fixture-secret-do-not-leak"
	spool := filepath.Join(t.TempDir(), "audit.jsonl")
	var stdout, stderr bytes.Buffer
	const reference = "kei://connectors/connector-1/api_token"
	t.Setenv("API_TOKEN", reference)
	parent := os.Environ()
	code := runCommand([]string{"--connector", "connector-1", "--", "/bin/sh", "-c", "printenv API_TOKEN; printenv API_TOKEN >&2"}, &stdout, &stderr, Config{AppendAudit: func(record []byte) error { return os.WriteFile(spool, append(record, '\n'), 0600) }}, parent, testRunResolver{value: secret}, nil)
	if code != 0 {
		t.Fatalf("exit = %d; stderr=%q", code, stderr.String())
	}
	if strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) {
		t.Fatal("credential leaked in child output")
	}
	if !strings.Contains(stdout.String(), "[REDACTED]") || !strings.Contains(stderr.String(), "[REDACTED]") {
		t.Fatalf("output not redacted: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if os.Getenv("API_TOKEN") != reference {
		t.Fatalf("parent environment changed: API_TOKEN=%q", os.Getenv("API_TOKEN"))
	}
	data, err := os.ReadFile(spool)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) || strings.Contains(string(data), "kei://connectors/") {
		t.Fatalf("credential/reference leaked into audit: %s", data)
	}
	if !strings.Contains(string(data), "connector-1") || !strings.Contains(string(data), "api_token") {
		t.Fatalf("audit omitted connector identity/field: %s", data)
	}
}

func TestRunFailsClosedAndPrintsConnectURLOnlyToStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := false
	marker := filepath.Join(t.TempDir(), "should-not-execute")
	code := runCommand([]string{"--", "/bin/sh", "-c", "touch " + marker}, &stdout, &stderr, Config{}, []string{"API_TOKEN=kei://connectors/connector-1/api_token"}, testRunResolver{link: "https://console.example/connect/connector-1", err: errors.New("missing")}, func(string, []string, []string) int { called = true; return 0 })
	if code == 0 || called {
		t.Fatalf("missing credential did not fail closed: exit=%d called=%v", code, called)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "https://console.example/connect/connector-1") {
		t.Fatalf("connect URL channel wrong: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if strings.Contains(stderr.String(), "kei://connectors/") {
		t.Fatal("credential reference leaked to stderr")
	}
}

func TestRunNeverSurfacesResolvedSecretOnSuccessOrFailure(t *testing.T) {
	const secret = "fake-secret-never-print-this"
	const reference = "kei://connectors/connector-1/api_token"
	tests := []struct {
		name     string
		resolver testRunResolver
		child    bool
		wantExit int
	}{
		{name: "unresolved", resolver: testRunResolver{err: fmt.Errorf("backend detail: %s", secret)}, wantExit: 1},
		{name: "denied", resolver: testRunResolver{err: fmt.Errorf("policy detail: %s", secret)}, wantExit: 1},
		{name: "child-exit-nonzero", resolver: testRunResolver{value: secret}, child: true, wantExit: 9},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr, audit bytes.Buffer
			childArgs := []string{"--", "/bin/sh", "-c", "printf '%s\\n' \"$API_TOKEN\"; printf '%s\\n' \"$API_TOKEN\" >&2; exit 9"}
			if !tc.child {
				childArgs = []string{"--", "/bin/sh", "-c", "exit 0"}
			}
			code := runCommand(childArgs, &stdout, &stderr, Config{AppendAudit: func(record []byte) error { _, err := audit.Write(record); return err }}, []string{"API_TOKEN=" + reference}, tc.resolver, nil)
			if code != tc.wantExit {
				t.Fatalf("exit=%d want=%d", code, tc.wantExit)
			}
			if !tc.child && (!strings.Contains(stderr.String(), "connector-1") || !strings.Contains(stderr.String(), "api_token")) {
				t.Fatal("credential error omitted reference id/field")
			}
			for where, value := range map[string]string{"stdout": stdout.String(), "stderr": stderr.String(), "audit": audit.String(), "error text": stderr.String(), "reason error": runReasonError{"policy_denied"}.Error()} {
				if strings.Contains(value, secret) {
					t.Fatalf("credential appeared in %s", where)
				}
			}
			if !strings.Contains(audit.String(), "connector-1") || !strings.Contains(audit.String(), "api_token") {
				t.Fatal("audit omitted reference id/field")
			}
			if tc.child && (!strings.Contains(stdout.String(), "[REDACTED]") || !strings.Contains(stderr.String(), "[REDACTED]")) {
				t.Fatal("child output was not masked")
			}
		})
	}
}

func TestDeliveredRunResolverResolvesOAuth(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000000123"
	secretRef := "aws-secrets-manager://region/connectors/" + id + "/api_token"
	value := "oauth-secret-value"
	store := &fakeRunSecretStore{value: &value}
	auth := &fakeRunAuthorization{response: &invoke.Response{Decision: "allow", Connector: &invoke.Descriptor{Metadata: contract.Metadata{ID: id, CredentialRef: "api_token", CredentialSource: contract.CredentialSourceOAuth, Provider: contract.Provider("github")}, CredentialBackend: "aws-secrets-manager", CredentialSecretRef: secretRef}}}
	binding := &fakeRunCredentialBinding{backend: "aws-secrets-manager", ref: secretRef}
	resolver := deliveredRunResolver{cfg: Config{}, store: store, authorization: auth, credentialBinding: binding, subjectSource: &fakeSubjectSource{userID: "user-abc"}}
	got, _, err := resolver.Resolve(context.Background(), id, "api_token")
	if err != nil || got != value || store.reads != 1 {
		t.Fatalf("resolve=%q err=%v reads=%d", got, err, store.reads)
	}
}

func TestDeliveredRunResolverFailsOAuthSubjectMissing(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000000123"
	auth := &fakeRunAuthorization{response: &invoke.Response{Decision: "allow", Connector: &invoke.Descriptor{Metadata: contract.Metadata{ID: id, CredentialRef: "api_token", CredentialSource: contract.CredentialSourceOAuth, Provider: contract.Provider("github")}}}}
	resolver := deliveredRunResolver{cfg: Config{}, store: &fakeRunSecretStore{}, authorization: auth, credentialBinding: &fakeRunCredentialBinding{}}
	_, _, err := resolver.Resolve(context.Background(), id, "api_token")
	var reason runReasonError
	if !errors.As(err, &reason) || reason.reason != "subject_unlinked" {
		t.Fatalf("error=%v want reason subject_unlinked", err)
	}
}

func TestDeliveredRunResolverFailsOAuthWhenNoSubjectSource(t *testing.T) {
	t.Setenv("KEI_PROXY_USER_ID", "env-user")
	const id = "00000000-0000-4000-8000-000000000123"
	auth := &fakeRunAuthorization{response: &invoke.Response{Decision: "allow", Connector: &invoke.Descriptor{Metadata: contract.Metadata{ID: id, CredentialRef: "api_token", CredentialSource: contract.CredentialSourceOAuth, Provider: contract.Provider("github")}}}}
	resolver := deliveredRunResolver{cfg: Config{}, store: &fakeRunSecretStore{}, authorization: auth, credentialBinding: &fakeRunCredentialBinding{}}
	_, _, err := resolver.Resolve(context.Background(), id, "api_token")
	var reason runReasonError
	if !errors.As(err, &reason) || reason.reason != "subject_unlinked" {
		t.Fatalf("error=%v want reason subject_unlinked (env vars must have no effect on credential resolution)", err)
	}
}

func TestDeliveredRunResolverFailsOAuthProviderMissing(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000000123"
	auth := &fakeRunAuthorization{response: &invoke.Response{Decision: "allow", Connector: &invoke.Descriptor{Metadata: contract.Metadata{ID: id, CredentialRef: "api_token", CredentialSource: contract.CredentialSourceOAuth}}}}
	resolver := deliveredRunResolver{cfg: Config{}, store: &fakeRunSecretStore{}, authorization: auth, credentialBinding: &fakeRunCredentialBinding{}, subjectSource: &fakeSubjectSource{userID: "user-abc"}}
	_, _, err := resolver.Resolve(context.Background(), id, "api_token")
	var reason runReasonError
	if !errors.As(err, &reason) || reason.reason != "unresolved_reference" {
		t.Fatalf("error=%v want reason unresolved_reference", err)
	}
}

func TestDeliveredRunResolverFailsOAuthConnectRequired(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000000123"
	auth := &fakeRunAuthorization{response: &invoke.Response{Decision: "allow", Connector: &invoke.Descriptor{Metadata: contract.Metadata{ID: id, CredentialRef: "api_token", CredentialSource: contract.CredentialSourceOAuth, Provider: contract.Provider("github")}}}}
	binding := &fakeRunCredentialBinding{connectURL: "https://console.example/connect/github", err: errors.New("not found")}
	resolver := deliveredRunResolver{cfg: Config{}, store: &fakeRunSecretStore{}, authorization: auth, credentialBinding: binding, subjectSource: &fakeSubjectSource{userID: "user-abc"}}
	_, connectURL, err := resolver.Resolve(context.Background(), id, "api_token")
	var reason runReasonError
	if !errors.As(err, &reason) || reason.reason != "connect_required" {
		t.Fatalf("error=%v want reason connect_required", err)
	}
	if connectURL != "https://console.example/connect/github" {
		t.Fatalf("connectURL=%q", connectURL)
	}
}

func TestDeliveredRunResolverFailsOAuthCredentialBindingFails(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000000123"
	auth := &fakeRunAuthorization{response: &invoke.Response{Decision: "allow", Connector: &invoke.Descriptor{Metadata: contract.Metadata{ID: id, CredentialRef: "api_token", CredentialSource: contract.CredentialSourceOAuth, Provider: contract.Provider("github")}}}}
	binding := &fakeRunCredentialBinding{err: errors.New("server error")}
	resolver := deliveredRunResolver{cfg: Config{}, store: &fakeRunSecretStore{}, authorization: auth, credentialBinding: binding, subjectSource: &fakeSubjectSource{userID: "user-abc"}}
	_, _, err := resolver.Resolve(context.Background(), id, "api_token")
	var reason runReasonError
	if !errors.As(err, &reason) || reason.reason != "unresolved_reference" {
		t.Fatalf("error=%v want reason unresolved_reference", err)
	}
}

func TestRunInjectsOAuthOnlyMasksAndAuditsWithoutCredential(t *testing.T) {
	const secret = "oauth-secret-do-not-leak"
	spool := filepath.Join(t.TempDir(), "audit.jsonl")
	var stdout, stderr bytes.Buffer
	const reference = "kei://connectors/connector-1/api_token"
	t.Setenv("API_TOKEN", reference)
	parent := os.Environ()
	code := runCommand([]string{"--connector", "connector-1", "--", "/bin/sh", "-c", "printenv API_TOKEN; printenv API_TOKEN >&2"}, &stdout, &stderr, Config{AppendAudit: func(record []byte) error { return os.WriteFile(spool, append(record, '\n'), 0600) }}, parent, testRunResolver{value: secret}, nil)
	if code != 0 {
		t.Fatalf("exit = %d; stderr=%q", code, stderr.String())
	}
	if strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) {
		t.Fatal("OAuth credential leaked in child output")
	}
	if !strings.Contains(stdout.String(), "[REDACTED]") || !strings.Contains(stderr.String(), "[REDACTED]") {
		t.Fatalf("output not redacted: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if os.Getenv("API_TOKEN") != reference {
		t.Fatalf("parent environment changed: API_TOKEN=%q", os.Getenv("API_TOKEN"))
	}
	data, err := os.ReadFile(spool)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatalf("OAuth credential leaked into audit: %s", data)
	}
}

func TestHTTPCredentialBindingClientResolves(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("bad auth: %s", r.Header.Get("Authorization"))
		}
		if !strings.HasSuffix(r.URL.Path, "/user-abc/services/github") {
			t.Fatalf("bad path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secret_backend":"aws-secrets-manager","secret_ref":"ref/to/secret"}`))
	}))
	defer server.Close()
	client := newHTTPCredentialBindingClient(server.URL)
	backend, ref, connectURL, err := client.Resolve(context.Background(), "test-token", "user-abc", "github")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if backend != "aws-secrets-manager" || ref != "ref/to/secret" || connectURL != "" {
		t.Fatalf("backend=%q ref=%q connectURL=%q", backend, ref, connectURL)
	}
}

func TestHTTPCredentialBindingClientReturnsConnectURLOnNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	client := newHTTPCredentialBindingClient(server.URL)
	backend, ref, connectURL, err := client.Resolve(context.Background(), "test-token", "user-abc", "github")
	if err == nil {
		t.Fatal("expected error for 404")
	}
	if backend != "" || ref != "" {
		t.Fatalf("expected empty backend/ref on 404: backend=%q ref=%q", backend, ref)
	}
	if connectURL == "" {
		t.Fatal("expected connect URL on 404")
	}
	if !strings.Contains(connectURL, "github") || !strings.Contains(connectURL, "user-abc") {
		t.Fatalf("connect URL missing params: %q", connectURL)
	}
}

func TestHTTPCredentialBindingClientFailsOnServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	client := newHTTPCredentialBindingClient(server.URL)
	backend, ref, connectURL, err := client.Resolve(context.Background(), "test-token", "user-abc", "github")
	if err == nil {
		t.Fatal("expected error for 500")
	}
	if backend != "" || ref != "" || connectURL != "" {
		t.Fatalf("expected empty values on 500: backend=%q ref=%q connectURL=%q", backend, ref, connectURL)
	}
}

func TestRedactingWriterMasksSecretAcrossWrites(t *testing.T) {
	var out bytes.Buffer
	w := newRedactingWriter(&out, []string{"abcdef"})
	_, _ = w.Write([]byte("prefixabc"))
	_, _ = w.Write([]byte("defsuffix"))
	_ = w.Close()
	if got := out.String(); strings.Contains(got, "abcdef") || !strings.Contains(got, "[REDACTED]") || !strings.Contains(got, "prefix") || !strings.Contains(got, "suffix") {
		t.Fatalf("redacted stream = %q", got)
	}
}

func TestAppendRunAuditLogsAppendError(t *testing.T) {
	var stderr bytes.Buffer
	wantErr := fmt.Errorf("disk full")
	appendRunAudit(&stderr, Config{AppendAudit: func([]byte) error { return wantErr }}, nil, nil, "test-cmd", []string{"arg1"}, "success", 0)
	if stderr.Len() == 0 {
		t.Fatal("expected an error on stderr")
	}
	if !strings.Contains(stderr.String(), "audit: failed to append credential audit record") {
		t.Fatalf("stderr = %q, want audit failure message", stderr.String())
	}
}

func TestAppendRunAuditLogsMarshalError(t *testing.T) {
	var stderr bytes.Buffer
	appendRunAudit(&stderr, Config{}, nil, nil, "test-cmd", []string{"arg1"}, "success", 0)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr on success path, got %q", stderr.String())
	}
}

// HAI-1000: kei-proxy run releases an external credential_ref that credential
// sync resolved, reading the secret at that external ref.
func TestDeliveredRunResolverReadsAnExternalRef(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000001000"
	externalRef := "aws-secrets-manager://us-east-1/customer/crm/api-key"
	index := filepath.Join(t.TempDir(), "connector-credentials.json")
	if err := credentials.WriteConnectorReference(index, credentials.ConnectorReference{ConnectorID: id, Field: "api_key", SecretBackend: "aws-secrets-manager", SecretRef: externalRef, External: true}); err != nil {
		t.Fatal(err)
	}
	value := "fake-external-value"
	store := &recordingRunSecretStore{value: value}
	auth := &fakeRunAuthorization{response: &invoke.Response{Decision: "allow", Connector: &invoke.Descriptor{Metadata: contract.Metadata{ID: id, CredentialRef: externalRef, CredentialSource: contract.CredentialSourceOpaqueRef}, CredentialBackend: "aws-secrets-manager"}}}
	got, _, err := (deliveredRunResolver{cfg: Config{RuntimeStateDir: filepath.Dir(index)}, store: store, authorization: auth}).Resolve(context.Background(), id, "api_key")
	if err != nil || got != value || len(store.refs) != 1 || store.refs[0] != externalRef {
		t.Fatalf("resolve=%q err=%v refs=%v", got, err, store.refs)
	}
	// Another backend on the descriptor is refused before any read.
	auth.response.Connector.CredentialBackend = "azure-key-vault"
	store.refs = nil
	if _, _, err := (deliveredRunResolver{cfg: Config{RuntimeStateDir: filepath.Dir(index)}, store: store, authorization: auth}).Resolve(context.Background(), id, "api_key"); err == nil || len(store.refs) != 0 {
		t.Fatalf("backend mismatch: err=%v refs=%v", err, store.refs)
	}
}

type recordingRunSecretStore struct {
	value string
	refs  []string
}

func (s *recordingRunSecretStore) Get(_ context.Context, _, ref string) (*string, error) {
	s.refs = append(s.refs, ref)
	v := s.value
	return &v, nil
}
func (*recordingRunSecretStore) Put(context.Context, string, string, string) error { return nil }
func (*recordingRunSecretStore) Delete(context.Context, string, string) error      { return nil }
func (*recordingRunSecretStore) Validate(context.Context, string, string) error    { return nil }

// HAI-1023: kei-proxy run verifies an external entry by its bare
// credential_ref, so a catalog-qualified Azure ref needs no vault env.
func TestDeliveredRunResolverVerifiesCatalogSecretRefWithoutVaultEnv(t *testing.T) {
	t.Setenv("KEI_SECRETS_AZURE_VAULT_URL", "")
	const id = "00000000-0000-4000-8000-000000001000"
	const qualified = "https://acme.vault.azure.net/secrets/crm-api-key"
	index := filepath.Join(t.TempDir(), "connector-credentials.json")
	if err := credentials.WriteExternalConnectorReference(index, credentials.ConnectorReference{ConnectorID: id, Field: "api_key", SecretBackend: "azure-key-vault", SecretRef: qualified, External: true}, "crm-api-key"); err != nil {
		t.Fatal(err)
	}
	store := &recordingRunSecretStore{value: "fake-external-value"}
	auth := &fakeRunAuthorization{response: &invoke.Response{Decision: "allow", Connector: &invoke.Descriptor{Metadata: contract.Metadata{ID: id, CredentialRef: "crm-api-key", CredentialSource: contract.CredentialSourceOpaqueRef}, CredentialBackend: "azure-key-vault"}}}
	got, _, err := (deliveredRunResolver{cfg: Config{RuntimeStateDir: filepath.Dir(index)}, store: store, authorization: auth}).Resolve(context.Background(), id, "api_key")
	if err != nil || got != "fake-external-value" || len(store.refs) != 1 || store.refs[0] != qualified {
		t.Fatalf("resolve=%q err=%v refs=%v", got, err, store.refs)
	}
}
