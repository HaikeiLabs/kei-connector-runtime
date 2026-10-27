package invoke

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The catalog client posts the request to /api/v1/data-connectors/invoke
// with the bearer token, and fails closed on any non-200 status so a
// rejected or unavailable control plane never yields a decision.
func TestClientInvokePostsToCatalogAndFailsClosed(t *testing.T) {
	var gotPath, gotAuth string
	var gotBody Request
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.WriteHeader(status)
		if status == http.StatusOK {
			_ = json.NewEncoder(w).Encode(map[string]any{"decision": "allow"})
		}
	}))
	t.Cleanup(srv.Close)

	req := Request{HarnessToken: "rt", ConnectorID: "conn-1", Capability: "credential", Action: "use", Resource: "kei://connectors/conn-1/token", TraceID: "t"}
	resp, err := NewClient(srv.URL, time.Second).WithBearerToken("rt").Invoke(context.Background(), req)
	if err != nil || resp == nil || resp.Decision != "allow" {
		t.Fatalf("allow: resp=%+v err=%v", resp, err)
	}
	if gotPath != "/api/v1/data-connectors/invoke" || gotAuth != "Bearer rt" {
		t.Fatalf("path=%q auth=%q", gotPath, gotAuth)
	}
	if gotBody != req {
		t.Fatalf("body=%+v want %+v", gotBody, req)
	}

	for _, tc := range []struct {
		name   string
		status int
	}{{"unauthorized", http.StatusUnauthorized}, {"server error", http.StatusInternalServerError}} {
		t.Run(tc.name, func(t *testing.T) {
			status = tc.status
			if _, err := NewClient(srv.URL, time.Second).WithBearerToken("rt").Invoke(context.Background(), req); err == nil {
				t.Fatalf("status %d must fail closed", tc.status)
			}
		})
	}
}

// ParseConnectorRef splits kei://connectors/<id>/<field> and rejects
// everything else.
func TestParseConnectorRef(t *testing.T) {
	for _, tc := range []struct {
		ref              string
		connectorID, fld string
		ok               bool
	}{
		{"kei://connectors/conn-1/token", "conn-1", "token", true},
		{"kei://connectors/conn-1/api_key", "conn-1", "api_key", true},
		{"", "", "", false},
		{"https://example.com", "", "", false},
		{"kei://connectors//token", "", "", false},
		{"kei://connectors/conn-1/", "", "", false},
		{"kei://connectors/conn-1/a/b", "", "", false},
	} {
		connectorID, field, ok := ParseConnectorRef(tc.ref)
		if ok != tc.ok || connectorID != tc.connectorID || field != tc.fld {
			t.Errorf("ParseConnectorRef(%q) = %q, %q, %v want %q, %q, %v", tc.ref, connectorID, field, ok, tc.connectorID, tc.fld, tc.ok)
		}
	}
}
