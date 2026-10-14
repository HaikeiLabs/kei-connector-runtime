package mcproute

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

// HAI-581 item 3 (ADR-036 §3.3, §4.8, contract "mcp.credential_fields exact
// schema"): a secret_ref mcp connector sends each credential_fields entry's
// secret, resolved from kei://connectors/<id>/<field>, in exactly its header,
// with its optional prefix. Nothing else carries a credential.

const (
	apiKeyValue = "dd-api-key-value-581"
	appKeyValue = "dd-app-key-value-581"
)

type fakeSecretFields struct {
	mu     sync.Mutex
	values map[string]string
	asked  []string
}

func (f *fakeSecretFields) Resolve(_ context.Context, d policybundle.Connector, field string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, d.ID+"/"+field)
	v, ok := f.values[field]
	if !ok {
		return "", errors.New("not delivered")
	}
	return v, nil
}

var datadogFields = []policybundle.MCPCredentialField{
	{Field: "api_key", Header: "DD-API-KEY"},
	{Field: "app_key", Header: "DD-APPLICATION-KEY"},
}

func secretRig(t *testing.T, fields []policybundle.MCPCredentialField, values map[string]string, onCall http.HandlerFunc) (*Handler, string, *listingUpstream, *fakeSecretFields, *bytes.Buffer) {
	t.Helper()
	tool := namedTool("search")
	up := newListingUpstream(t, tool)
	up.onCall = onCall
	cat := catalogFor(up.srv.URL, approvedTools(t, tool))
	cat.connectors[0].MCP.AuthMethod = "secret_ref"
	cat.connectors[0].MCP.CredentialFields = fields
	secrets := &fakeSecretFields{values: values}
	var logs bytes.Buffer
	reg, key := testKey(t)
	h := NewHandler(Config{KeyRegistry: reg, Authorizer: verdictAuthorizer{}, Catalog: cat, Secrets: secrets, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	h.checkSSRF = noSSRFCheck
	h.dialCtl = noDialCheck
	return h, key, up, secrets, &logs
}

func TestMCPRouteSecretRef_SendsExactlyTheConfiguredHeaders(t *testing.T) {
	h, key, up, secrets, _ := secretRig(t, datadogFields, map[string]string{"api_key": apiKeyValue, "app_key": appKeyValue}, nil)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callBody("search")))

	if up.calls.Load() != 1 {
		t.Fatalf("call not forwarded: %s", w.Body.Bytes())
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	for i, hdr := range up.seen {
		if hdr.Get("DD-API-KEY") != apiKeyValue || hdr.Get("DD-APPLICATION-KEY") != appKeyValue || hdr.Get("Authorization") != "" {
			t.Fatalf("upstream request %d headers %v, want exactly the two credential headers", i, hdr)
		}
	}
	if len(secrets.asked) == 0 || secrets.asked[0] != "conn-1/api_key" {
		t.Fatalf("resolved %v, want each field of conn-1", secrets.asked)
	}
	if strings.Contains(w.Body.String(), apiKeyValue) {
		t.Fatal("a secret reached the harness")
	}
}

func TestMCPRouteSecretRef_PrefixIsPrepended(t *testing.T) {
	h, key, up, _, _ := secretRig(t, []policybundle.MCPCredentialField{{Field: "token", Header: "X-Api-Token", Prefix: "Bearer "}}, map[string]string{"token": apiKeyValue}, nil)

	h.ServeHTTP(httptest.NewRecorder(), routeRequest(key, callBody("search")))

	up.mu.Lock()
	defer up.mu.Unlock()
	if len(up.seen) == 0 {
		t.Fatal("the upstream received no request")
	}
	if got := up.seen[0].Get("X-Api-Token"); got != "Bearer "+apiKeyValue {
		t.Fatalf("X-Api-Token = %q, want the prefix then the secret", got)
	}
}

func TestMCPRouteSecretRef_DenialsReachNoUpstream(t *testing.T) {
	both := map[string]string{"api_key": apiKeyValue, "app_key": appKeyValue}
	for name, tc := range map[string]struct {
		fields []policybundle.MCPCredentialField
		values map[string]string
		noSrc  bool
	}{
		"credential_fields absent": {fields: nil, values: both},
		"a field not delivered":    {fields: datadogFields, values: map[string]string{"api_key": apiKeyValue}},
		"no secret source":         {fields: datadogFields, values: both, noSrc: true},
		"duplicate field":          {fields: []policybundle.MCPCredentialField{{Field: "api_key", Header: "X-A"}, {Field: "api_key", Header: "X-B"}}, values: both},
		"duplicate header (case)":  {fields: []policybundle.MCPCredentialField{{Field: "api_key", Header: "X-Key"}, {Field: "app_key", Header: "x-key"}}, values: both},
		"secret with a line break": {fields: datadogFields, values: map[string]string{"api_key": apiKeyValue, "app_key": "v" + string(rune(13)) + string(rune(10)) + "X-Injected: 1"}},
	} {
		t.Run(name, func(t *testing.T) {
			h, key, up, _, _ := secretRig(t, tc.fields, tc.values, nil)
			if tc.noSrc {
				h.config.Secrets = nil
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, routeRequest(key, callBody("search")))

			assertDenied(t, w, -31424, "credential_unavailable")
			if up.lists.Load()+up.calls.Load() != 0 {
				t.Fatal("the upstream was reached")
			}
		})
	}
}

func TestMCPRouteSecretRef_DeniedHeaderNames(t *testing.T) {
	for _, header := range []string{"Authorization", "authorization", "Host", "Content-Length", "Cookie", "Mcp-Session-Id", "MCP-Protocol-Version", "Content-Type", "Accept"} {
		h, key, up, _, _ := secretRig(t, []policybundle.MCPCredentialField{{Field: "api_key", Header: header}}, map[string]string{"api_key": apiKeyValue}, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, routeRequest(key, callBody("search")))

		assertDenied(t, w, -31424, "credential_unavailable")
		if up.lists.Load()+up.calls.Load() != 0 {
			t.Fatalf("header %s: the upstream was reached", header)
		}
	}
}

func TestMCPRouteSecretRef_EchoOfAnySecretIsDropped(t *testing.T) {
	h, key, _, _, _ := secretRig(t, datadogFields, map[string]string{"api_key": apiKeyValue, "app_key": appKeyValue}, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"%s"}]}}`, appKeyValue)
	})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callBody("search")))

	assertDenied(t, w, -31502, "credential_echo")
}

func TestMCPRouteSecretRef_SecretsAreNeverLogged(t *testing.T) {
	h, key, _, _, logs := secretRig(t, datadogFields, map[string]string{"api_key": apiKeyValue, "app_key": appKeyValue}, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})

	h.ServeHTTP(httptest.NewRecorder(), routeRequest(key, callBody("search")))

	if logs.Len() == 0 {
		t.Fatal("expected the upstream failure to be logged")
	}
	if strings.Contains(logs.String(), apiKeyValue) || strings.Contains(logs.String(), appKeyValue) {
		t.Fatalf("a secret reached the log: %s", logs.String())
	}
}

func noSSRFCheck(*url.URL) error                        { return nil }
func noDialCheck(string, string, syscall.RawConn) error { return nil }
