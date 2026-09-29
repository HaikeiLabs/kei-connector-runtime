package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/connectortest"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/input"
)

func apiCall(r *connectortest.Routes, in any, maxBytes int64) connector.Call {
	call := connectortest.Call(r, contract.ProviderHTTPAPI, "http.get", contract.ActionRead, "leads", in, "fake-http-key")
	call.Meta.HTTPAPI = &contract.HTTPAPI{
		RegisteredBaseURL: "https://api.example.com/v1", RegisteredHostname: "api.example.com",
		AllowedMethods: []contract.HTTPMethod{contract.HTTPMethodGet}, AllowedPathPatterns: []string{"/leads"},
		QueryAllowlist: []string{"limit"}, RequestMaxBytes: 1024, ResponseMaxBytes: maxBytes, TimeoutMS: 5000,
		CredentialInjection: contract.CredentialInjection{Location: contract.CredentialInjectionHeader, Name: "X-API-Key"},
		Redaction:           contract.RedactionRules{Headers: []string{"X-API-Key"}, ResponseFields: []string{"email"}},
	}
	return call
}

func routes(t *testing.T, body string) *connectortest.Routes {
	r := connectortest.NewRoutes()
	r.Handle("api.example.com", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v1/leads" || req.URL.Query().Get("limit") != "5" || req.Header.Get("X-API-Key") != "fake-http-key" {
			t.Errorf("request = %s %v", req.URL, req.Header)
		}
		_, _ = io.WriteString(w, body)
	})
	return r
}

func TestGetInjectsTheKeyAndRedactsConfiguredFields(t *testing.T) {
	in := input.HTTPRequest{Method: "GET", Path: "/leads", Query: map[string][]string{"limit": {"5"}}}
	got, err := Connector{}.Execute(context.Background(), apiCall(routes(t, `{"records":[{"id":1,"email":"x@example.test"}]}`), in, 65536))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(got)
	if !strings.Contains(string(raw), `"status_code":200`) || strings.Contains(string(raw), "x@example.test") || strings.Contains(string(raw), "fake-http-key") {
		t.Fatalf("result = %s", raw)
	}
}

func TestRejectsUnregisteredPathsAndOversizeResponses(t *testing.T) {
	r := connectortest.NewRoutes()
	bad := input.HTTPRequest{Method: "GET", Path: "/admin"}
	if _, err := (Connector{}).Execute(context.Background(), apiCall(r, bad, 65536)); !errors.Is(err, connector.ErrInput) || r.Count() != 0 {
		t.Fatalf("unregistered path err = %v, requests = %d", err, r.Count())
	}
	in := input.HTTPRequest{Method: "GET", Path: "/leads", Query: map[string][]string{"limit": {"5"}}}
	if _, err := (Connector{}).Execute(context.Background(), apiCall(routes(t, strings.Repeat("x", 200)), in, 100)); !errors.Is(err, connector.ErrTooLarge) {
		t.Fatalf("oversize err = %v", err)
	}
}
