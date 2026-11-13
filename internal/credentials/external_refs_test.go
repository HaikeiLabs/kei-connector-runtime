package credentials

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// HAI-1000: connectors whose credential_ref is external (a secret the customer
// keeps in their own secret manager) are resolved from the catalog's
// external-credential-refs list, not from a Kei delivery.

const (
	extConnectorA = "00000000-0000-4000-8000-00000000a001"
	extConnectorB = "00000000-0000-4000-8000-00000000b002"
	extRefA       = "aws-secrets-manager://us-east-1/customer/crm/api-key"
	extRefB       = "aws-secrets-manager://us-east-1/customer/billing/api-key"
	extSecret     = "super-secret-external-value"
)

type externalRefsCatalog struct {
	pages  map[string]externalCredentialRefsPage // keyed by page_token
	status int
	calls  int
	paths  []string
	auths  []string
}

func (c *externalRefsCatalog) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.calls++
		c.paths = append(c.paths, r.Method+" "+r.URL.Path)
		c.auths = append(c.auths, r.Header.Get("Authorization"))
		if c.status != 0 {
			w.WriteHeader(c.status)
			return
		}
		page, ok := c.pages[r.URL.Query().Get("page_token")]
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(page)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// refStore is a secrets.Store whose Validate succeeds only for known refs.
type refStore struct {
	known     map[string]bool
	validated []string
	gets      int
}

func (s *refStore) Get(context.Context, string, string) (*string, error) {
	s.gets++
	v := extSecret
	return &v, nil
}
func (s *refStore) Put(context.Context, string, string, string) error { return errors.New("read-only") }
func (s *refStore) Delete(context.Context, string, string) error      { return errors.New("read-only") }
func (s *refStore) Validate(_ context.Context, _ string, ref string) error {
	s.validated = append(s.validated, ref)
	if s.known[ref] {
		return nil
	}
	return errors.New("not found")
}

func externalConfig(t *testing.T, url string) Config {
	t.Helper()
	return Config{
		ControlPlaneURL:    url,
		RuntimeToken:       "runtime-token",
		Timeout:            5 * time.Second,
		ConnectorIndexPath: filepath.Join(t.TempDir(), "runtime", "connector-credentials.json"),
		SecretsBackend:     "aws-secrets-manager",
	}
}

func TestExternalCredentialRefsClientPaginates(t *testing.T) {
	catalog := &externalRefsCatalog{pages: map[string]externalCredentialRefsPage{
		"":   {Refs: []ExternalCredentialRef{{ConnectorID: extConnectorA, Field: "api_key", CredentialRef: extRefA, Status: "pending"}}, NextPageToken: "p2"},
		"p2": {Refs: []ExternalCredentialRef{{ConnectorID: extConnectorB, Field: "api_key", CredentialRef: extRefB, Status: "active"}}},
	}}
	srv := catalog.server(t)
	refs, listed, err := newExternalRefsClient(srv.URL, time.Second).ListExternalCredentialRefs(context.Background(), "runtime-token")
	if err != nil || !listed {
		t.Fatalf("listed=%v err=%v", listed, err)
	}
	if len(refs) != 2 || refs[0].ConnectorID != extConnectorA || refs[1].ConnectorID != extConnectorB || refs[1].Status != "active" {
		t.Fatalf("refs = %+v", refs)
	}
	for i, p := range catalog.paths {
		if p != "GET /api/v1/runtime/external-credential-refs" || catalog.auths[i] != "Bearer runtime-token" {
			t.Fatalf("request %d = %q auth %q", i, p, catalog.auths[i])
		}
	}
	if catalog.calls != 2 {
		t.Fatalf("calls = %d, want 2", catalog.calls)
	}
}

func TestExternalCredentialRefsClientTreats404AsNoRefs(t *testing.T) {
	catalog := &externalRefsCatalog{status: http.StatusNotFound}
	refs, listed, err := newExternalRefsClient(catalog.server(t).URL, time.Second).ListExternalCredentialRefs(context.Background(), "runtime-token")
	if err != nil || listed || len(refs) != 0 {
		t.Fatalf("refs=%v listed=%v err=%v", refs, listed, err)
	}
}

func TestExternalCredentialRefsClientFailsOnServerError(t *testing.T) {
	catalog := &externalRefsCatalog{status: http.StatusInternalServerError}
	if _, _, err := newExternalRefsClient(catalog.server(t).URL, time.Second).ListExternalCredentialRefs(context.Background(), "runtime-token"); err == nil {
		t.Fatal("want an error for a 500")
	}
}

func TestResolveExternalRefsWritesExternalEntry(t *testing.T) {
	catalog := &externalRefsCatalog{pages: map[string]externalCredentialRefsPage{
		"": {Refs: []ExternalCredentialRef{{ConnectorID: extConnectorA, Field: "api_key", CredentialRef: extRefA, Status: "pending"}}},
	}}
	cfg := externalConfig(t, catalog.server(t).URL)
	store := &refStore{known: map[string]bool{extRefA: true}}
	out, err := ResolveExternalRefs(context.Background(), cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Listed || len(out.Resolved) != 1 || out.Resolved[0] != extConnectorA || len(out.Unresolved) != 0 {
		t.Fatalf("output = %+v", out)
	}
	if store.gets != 0 {
		t.Fatalf("resolve read the secret value %d times; it must only validate", store.gets)
	}
	entry, err := ReadConnectorReference(cfg.ConnectorIndexPath, extConnectorA, "api_key")
	if err != nil {
		t.Fatal(err)
	}
	want := ConnectorReference{ConnectorID: extConnectorA, Field: "api_key", SecretBackend: "aws-secrets-manager", SecretRef: extRefA, External: true}
	if entry != want {
		t.Fatalf("entry = %+v, want %+v", entry, want)
	}
}

func TestResolveExternalRefsAcceptsABareAWSSecretName(t *testing.T) {
	catalog := &externalRefsCatalog{pages: map[string]externalCredentialRefsPage{
		"": {Refs: []ExternalCredentialRef{{ConnectorID: extConnectorA, Field: "api_key", CredentialRef: "customer/crm/api-key", Status: "pending"}}},
	}}
	cfg := externalConfig(t, catalog.server(t).URL)
	store := &refStore{known: map[string]bool{"aws-secrets-manager:///customer/crm/api-key": true}}
	out, err := ResolveExternalRefs(context.Background(), cfg, store)
	if err != nil || len(out.Resolved) != 1 {
		t.Fatalf("out=%+v err=%v validated=%v", out, err, store.validated)
	}
	entry, err := ReadExternalConnectorReference(cfg.ConnectorIndexPath, extConnectorA, "aws-secrets-manager", "customer/crm/api-key")
	if err != nil || entry.SecretRef != "aws-secrets-manager:///customer/crm/api-key" {
		t.Fatalf("entry=%+v err=%v", entry, err)
	}
}

func TestResolveExternalRefsUnresolvedWritesNoneAndRemovesStale(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "runtime", "connector-credentials.json")
	// A stale external entry from an earlier run, and a Kei-delivered entry
	// that must never be touched by external resolution.
	if err := WriteConnectorReference(cfgPath, ConnectorReference{ConnectorID: extConnectorA, Field: "api_key", SecretBackend: "aws-secrets-manager", SecretRef: extRefA, External: true}); err != nil {
		t.Fatal(err)
	}
	delivered := ConnectorReference{ConnectorID: extConnectorB, Field: "api_token", SecretBackend: "aws-secrets-manager", SecretRef: "aws-secrets-manager://region/connectors/" + extConnectorB + "/api_token", Generation: 1}
	if err := WriteConnectorReference(cfgPath, delivered); err != nil {
		t.Fatal(err)
	}
	catalog := &externalRefsCatalog{pages: map[string]externalCredentialRefsPage{
		"": {Refs: []ExternalCredentialRef{
			{ConnectorID: extConnectorA, Field: "api_key", CredentialRef: extRefA, Status: "active"},
			{ConnectorID: extConnectorB, Field: "api_key", CredentialRef: extRefB, Status: "pending"},
		}},
	}}
	cfg := externalConfig(t, catalog.server(t).URL)
	cfg.ConnectorIndexPath = cfgPath
	store := &refStore{known: map[string]bool{}} // nothing resolves any more
	out, err := ResolveExternalRefs(context.Background(), cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Resolved) != 0 || len(out.Unresolved) != 2 || out.Removed != 1 {
		t.Fatalf("output = %+v", out)
	}
	if _, err := ReadConnectorReference(cfgPath, extConnectorA, "api_key"); !errors.Is(err, ErrConnectorReferenceNotFound) {
		t.Fatalf("stale external entry still present: %v", err)
	}
	if _, err := ReadConnectorReference(cfgPath, extConnectorB, "api_key"); !errors.Is(err, ErrConnectorReferenceNotFound) {
		t.Fatalf("unresolved ref wrote an entry: %v", err)
	}
	if got, err := ReadConnectorReference(cfgPath, extConnectorB, "api_token"); err != nil || got != delivered {
		t.Fatalf("delivered entry changed: %+v %v", got, err)
	}
	ids, err := ResolvedExternalConnectorIDs(cfgPath)
	if err != nil || len(ids) != 1 || ids[0] != extConnectorB {
		t.Fatalf("activations = %v err=%v (only the delivered connector should remain)", ids, err)
	}
}

func TestResolveExternalRefsPrunesExternalEntriesNoLongerListed(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "runtime", "connector-credentials.json")
	if err := WriteConnectorReference(cfgPath, ConnectorReference{ConnectorID: extConnectorA, Field: "api_key", SecretBackend: "aws-secrets-manager", SecretRef: extRefA, External: true}); err != nil {
		t.Fatal(err)
	}
	catalog := &externalRefsCatalog{pages: map[string]externalCredentialRefsPage{"": {}}}
	cfg := externalConfig(t, catalog.server(t).URL)
	cfg.ConnectorIndexPath = cfgPath
	out, err := ResolveExternalRefs(context.Background(), cfg, &refStore{})
	if err != nil || out.Removed != 1 {
		t.Fatalf("out=%+v err=%v", out, err)
	}
}

func TestResolveExternalRefs404LeavesIndexAlone(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "runtime", "connector-credentials.json")
	if err := WriteConnectorReference(cfgPath, ConnectorReference{ConnectorID: extConnectorA, Field: "api_key", SecretBackend: "aws-secrets-manager", SecretRef: extRefA, External: true}); err != nil {
		t.Fatal(err)
	}
	catalog := &externalRefsCatalog{status: http.StatusNotFound}
	cfg := externalConfig(t, catalog.server(t).URL)
	cfg.ConnectorIndexPath = cfgPath
	out, err := ResolveExternalRefs(context.Background(), cfg, &refStore{})
	if err != nil || out.Listed || out.Removed != 0 {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	if _, err := ReadConnectorReference(cfgPath, extConnectorA, "api_key"); err != nil {
		t.Fatalf("404 removed an entry: %v", err)
	}
}

func TestResolveExternalRefsNeverEmitsTheSecretValue(t *testing.T) {
	catalog := &externalRefsCatalog{pages: map[string]externalCredentialRefsPage{
		"": {Refs: []ExternalCredentialRef{
			{ConnectorID: extConnectorA, Field: "api_key", CredentialRef: extRefA, Status: "pending"},
			{ConnectorID: extConnectorB, Field: "api_key", CredentialRef: extRefB, Status: "pending"},
		}},
	}}
	cfg := externalConfig(t, catalog.server(t).URL)
	store := &refStore{known: map[string]bool{extRefA: true}}
	stderr := captureStderr(t, func() {
		out, err := ResolveExternalRefs(context.Background(), cfg, store)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(out)
		if strings.Contains(string(data), extSecret) || strings.Contains(string(data), extRefA) {
			t.Fatalf("output leaks a value or ref: %s", data)
		}
	})
	if strings.Contains(stderr, extSecret) {
		t.Fatal("stderr contains the secret value")
	}
	index, err := os.ReadFile(cfg.ConnectorIndexPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(index), extSecret) {
		t.Fatal("index contains the secret value")
	}
}

func TestResolvedExternalConnectorIDsReportsExternalEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime", "connector-credentials.json")
	if err := WriteConnectorReference(path, ConnectorReference{ConnectorID: extConnectorA, Field: "api_key", SecretBackend: "aws-secrets-manager", SecretRef: extRefA, External: true}); err != nil {
		t.Fatal(err)
	}
	ids, err := ResolvedExternalConnectorIDs(path)
	if err != nil || len(ids) != 1 || ids[0] != extConnectorA {
		t.Fatalf("ids=%v err=%v", ids, err)
	}
}

func TestExternalEntryValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime", "connector-credentials.json")
	for name, entry := range map[string]ConnectorReference{
		"bad uuid":      {ConnectorID: "nope", Field: "api_key", SecretBackend: "aws-secrets-manager", SecretRef: extRefA, External: true},
		"bad field":     {ConnectorID: extConnectorA, Field: "API KEY", SecretBackend: "aws-secrets-manager", SecretRef: extRefA, External: true},
		"no backend":    {ConnectorID: extConnectorA, Field: "api_key", SecretRef: extRefA, External: true},
		"bad ref":       {ConnectorID: extConnectorA, Field: "api_key", SecretBackend: "aws-secrets-manager", SecretRef: "not a ref", External: true},
		"kei:// ref":    {ConnectorID: extConnectorA, Field: "api_key", SecretBackend: "custom", SecretRef: "kei://connectors/" + extConnectorA + "/api_key", External: true},
		"not external":  {ConnectorID: extConnectorA, Field: "api_key", SecretBackend: "aws-secrets-manager", SecretRef: extRefA},
		"secret as ref": {ConnectorID: extConnectorA, Field: "api_key", SecretBackend: "custom", SecretRef: "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", External: true},
	} {
		if err := WriteConnectorReference(path, entry); err == nil {
			t.Errorf("%s: write accepted an invalid entry", name)
		}
	}
}

func TestReadConnectorReferenceReturnsExternalEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime", "connector-credentials.json")
	entry := ConnectorReference{ConnectorID: extConnectorA, Field: "api_key", SecretBackend: "aws-secrets-manager", SecretRef: extRefA, External: true}
	if err := WriteConnectorReference(path, entry); err != nil {
		t.Fatal(err)
	}
	got, err := ReadConnectorReference(path, extConnectorA, "api_key")
	if err != nil || got != entry {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	got, err = ReadExternalConnectorReference(path, extConnectorA, "aws-secrets-manager", extRefA)
	if err != nil || got != entry {
		t.Fatalf("external lookup got=%+v err=%v", got, err)
	}
	if _, err := ReadExternalConnectorReference(path, extConnectorA, "aws-secrets-manager", extRefB); !errors.Is(err, ErrConnectorReferenceNotFound) {
		t.Fatalf("another ref: err=%v", err)
	}
	if _, err := ReadExternalConnectorReference(path, extConnectorA, "azure-key-vault", extRefA); !errors.Is(err, ErrConnectorReferenceMismatch) {
		t.Fatalf("another backend: err=%v", err)
	}
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = orig }()
	fn()
	_ = w.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	return buf.String()
}
