package connectorruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRuntimeClientStartsPlatformNeutralIdentityClaim(t *testing.T) {
	const token = "kh_live_runtime_test_token_1234567890"
	expires := time.Now().UTC().Add(15 * time.Minute).Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != identityClaimStartPath {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Fatalf("Authorization = %q", got)
		}
		if got := r.Header.Get("X-KEI-API-Key"); got != "" {
			t.Fatalf("console API key must not be sent by runtime: %q", got)
		}
		var input map[string]string
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"platform": "discord", "tenant_id": "", "platform_user_id": "user-123"}
		if fmt.Sprint(input) != fmt.Sprint(want) {
			t.Fatalf("request body = %#v, want %#v", input, want)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"claim_url":"https://kei.example/identity/claim#claim=secret-fragment","expires_at":%q}`, expires.Format(time.RFC3339))
	}))
	defer server.Close()

	result, err := NewRuntimeClient(server.URL, time.Second).(*runtimeClient).StartIdentityClaim(context.Background(), token, IdentityClaimStartRequest{
		Platform: "Discord", PlatformUserID: "user-123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ClaimURL != "https://kei.example/identity/claim#claim=secret-fragment" || !result.ExpiresAt.Equal(expires) {
		t.Fatalf("unexpected claim response: %#v", result)
	}
}

func TestRuntimeClientStartsTenantAwareIdentityClaim(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input IdentityClaimStartRequest
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Fatal(err)
		}
		if input.Platform != "slack" || input.TenantID != "team-9" || input.PlatformUserID != "member-4" {
			t.Fatalf("request identity = %#v", input)
		}
		fmt.Fprint(w, `{"claim_url":"https://kei.example/claim#claim=opaque","expires_at":"2030-01-01T00:00:00Z"}`)
	}))
	defer server.Close()
	_, err := NewRuntimeClient(server.URL, time.Second).(*runtimeClient).StartIdentityClaim(context.Background(), "runtime-token", IdentityClaimStartRequest{
		Platform: "slack", TenantID: "team-9", PlatformUserID: "member-4",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeClientIdentityClaimFailures(t *testing.T) {
	tests := []struct {
		name string
		code int
		body string
	}{
		{name: "proxy rejection", code: http.StatusBadGateway, body: `{"error":"secret must not leak"}`},
		{name: "invalid response", code: http.StatusOK, body: `{"claim_url":"not a url","expires_at":""}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.code)
				fmt.Fprint(w, test.body)
			}))
			defer server.Close()
			_, err := NewRuntimeClient(server.URL, time.Second).(*runtimeClient).StartIdentityClaim(context.Background(), "runtime-token", IdentityClaimStartRequest{
				Platform: "discord", PlatformUserID: "user-1",
			})
			if err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatalf("error = %v; expected safe failure", err)
			}
		})
	}
}

func TestRuntimeClientRejectsInvalidIdentityClaimInput(t *testing.T) {
	for _, request := range []IdentityClaimStartRequest{
		{Platform: "unsupported", PlatformUserID: "u"},
		{Platform: "discord"},
	} {
		if _, err := NewRuntimeClient("http://127.0.0.1:1", time.Second).(*runtimeClient).StartIdentityClaim(context.Background(), "token", request); err == nil {
			t.Fatalf("accepted invalid request %#v", request)
		}
	}
}

func TestRuntimeClientStartsWhatsAppIdentityClaim(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input IdentityClaimStartRequest
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Fatal(err)
		}
		if input.Platform != "whatsapp" || input.TenantID != "" || input.PlatformUserID != "+15555550100" {
			t.Fatalf("request identity = %#v", input)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"claim_url":"https://kei.example/claim#claim=opaque","expires_at":"2030-01-01T00:00:00Z"}`)
	}))
	defer server.Close()
	_, err := NewRuntimeClient(server.URL, time.Second).(*runtimeClient).StartIdentityClaim(context.Background(), "runtime-token", IdentityClaimStartRequest{
		Platform: "whatsapp", PlatformUserID: "+15555550100",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeClientRejectsWhatsAppWithTenant(t *testing.T) {
	_, err := NewRuntimeClient("http://127.0.0.1:1", time.Second).(*runtimeClient).StartIdentityClaim(context.Background(), "token", IdentityClaimStartRequest{
		Platform: "whatsapp", TenantID: "twilio-account", PlatformUserID: "+15555550100",
	})
	if err == nil || !strings.Contains(err.Error(), "empty tenant") {
		t.Fatalf("expected tenant rejection, got %v", err)
	}
}

func TestRuntimeClientRejectsInvalidWhatsAppIdentity(t *testing.T) {
	for _, req := range []IdentityClaimStartRequest{
		{Platform: "whatsapp", PlatformUserID: "15555550100"},
		{Platform: "whatsapp", PlatformUserID: "+05555550100"},
		{Platform: "whatsapp", PlatformUserID: "+123456"},
		{Platform: "whatsapp", PlatformUserID: "+1234567890123456"},
		{Platform: "whatsapp", PlatformUserID: "whatsapp:+15555550100"},
		{Platform: "whatsapp", PlatformUserID: "+1 555-555-0100"},
		{Platform: "whatsapp", PlatformUserID: "+1555ABC0100"},
	} {
		if _, err := NewRuntimeClient("http://127.0.0.1:1", time.Second).(*runtimeClient).StartIdentityClaim(context.Background(), "token", req); err == nil || !strings.Contains(err.Error(), "E.164") {
			t.Fatalf("expected E.164 rejection for %#v, got %v", req, err)
		}
	}
}
