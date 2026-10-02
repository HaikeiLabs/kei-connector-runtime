package run

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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

func TestDeliveredRunResolverFailsClosedForDenyMissingAndOAuth(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000000123"
	for _, tc := range []struct {
		name, decision, source, reason string
		indexed                        bool
	}{
		{name: "deny", decision: "deny", reason: "policy_denied", indexed: true},
		{name: "unresolved", decision: "allow", source: "opaque_ref", reason: "unresolved_reference"},
		{name: "oauth", decision: "allow", source: "oauth", reason: "oauth_not_supported", indexed: true},
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
	code := runCommand([]string{"--", "/bin/sh", "-c", "touch /tmp/kei-proxy-run-should-not-execute"}, &stdout, &stderr, Config{}, []string{"API_TOKEN=kei://connectors/connector-1/api_token"}, testRunResolver{link: "https://console.example/connect/connector-1", err: errors.New("missing")}, func(string, []string, []string) int { called = true; return 0 })
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
