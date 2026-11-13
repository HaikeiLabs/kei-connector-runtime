package runtime

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// HAI-1000: `kei-proxy credential sync` resolves the catalog's external
// credential refs after the delivery sync, and reports connectors only.

const (
	syncTestToken     = "runtime-token-sync-test"
	syncTestConnector = "00000000-0000-4000-8000-00000000c003"
	syncTestRef       = "crm-api-key"
)

type fakeCredentialConfig struct{ url string }

func (fakeCredentialConfig) IsRuntime() bool           { return true }
func (c fakeCredentialConfig) ControlPlaneURL() string { return c.url }
func (fakeCredentialConfig) Token() string             { return syncTestToken }
func (fakeCredentialConfig) SyncKeyID() string         { return "sync-key-1" }
func (fakeCredentialConfig) SyncPrivateKey() string    { return "unused-no-delivery-pending" }

type syncCatalog struct {
	mu        sync.Mutex
	refsCalls int
	refsAuth  string
	refsCode  int
}

func (c *syncCatalog) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/runtime/whoami":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "00000000-0000-4000-8000-0000000000aa", "org_id": "00000000-0000-4000-8000-0000000000bb", "platform": "cli"})
		case "/api/v1/runtime/credential-delivery:claim":
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/runtime/external-credential-refs":
			c.mu.Lock()
			c.refsCalls++
			c.refsAuth = r.Header.Get("Authorization")
			code := c.refsCode
			c.mu.Unlock()
			if code != 0 {
				w.WriteHeader(code)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"external_credential_refs": []map[string]string{{"connector_id": syncTestConnector, "field": "api_key", "credential_ref": syncTestRef, "status": "pending"}},
				"next_page_token":          "",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func runSyncForTest(t *testing.T, catalog *syncCatalog) (int, string, string) {
	t.Helper()
	t.Setenv("KEI_RUNTIME_STATE_DIR", t.TempDir())
	var stdout, stderr bytes.Buffer
	code := runCredentialSync(nil, &stdout, &stderr, fakeCredentialConfig{url: catalog.server(t).URL})
	for name, text := range map[string]string{"stdout": stdout.String(), "stderr": stderr.String()} {
		if strings.Contains(text, syncTestToken) || strings.Contains(text, syncTestRef) {
			t.Fatalf("%s leaks the token or the ref: %q", name, text)
		}
	}
	return code, stdout.String(), stderr.String()
}

func TestCredentialSyncResolvesExternalRefs(t *testing.T) {
	t.Setenv("KEI_SECRETS_BACKEND", "azure-key-vault")
	t.Setenv("KEI_SECRETS_AZURE_VAULT_URL", "")
	catalog := &syncCatalog{}
	code, stdout, stderr := runSyncForTest(t, catalog)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	if catalog.refsCalls != 1 || catalog.refsAuth != "Bearer "+syncTestToken {
		t.Fatalf("refs calls=%d", catalog.refsCalls)
	}
	var out struct {
		Claimed      bool `json:"claimed"`
		ExternalRefs *struct {
			Listed     bool     `json:"listed"`
			Unresolved []string `json:"unresolved_connector_ids"`
		} `json:"external_refs"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("stdout %q: %v", stdout, err)
	}
	if out.Claimed || out.ExternalRefs == nil || !out.ExternalRefs.Listed || len(out.ExternalRefs.Unresolved) != 1 || out.ExternalRefs.Unresolved[0] != syncTestConnector {
		t.Fatalf("output = %s", stdout)
	}
	if strings.Count(stderr, "KEI_SECRETS_AZURE_VAULT_URL") != 1 {
		t.Fatalf("want one warning naming KEI_SECRETS_AZURE_VAULT_URL, got %q", stderr)
	}
}

func TestCredentialSyncSurvivesAnExternalRefsFailure(t *testing.T) {
	t.Setenv("KEI_SECRETS_BACKEND", "")
	catalog := &syncCatalog{refsCode: http.StatusInternalServerError}
	code, stdout, stderr := runSyncForTest(t, catalog)
	if code != 0 || !strings.Contains(stderr, "resolve external credential refs") || strings.Contains(stdout, "external_refs") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
