package connectorruntime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestResolveIdentityStatusContract(t *testing.T) {
	statuses := []string{"unlinked", "linked_pending", "linked_approved", "linked_denied", "linked_unapproved", "linked_approved_other_workspace", "retry", "service_error"}
	for _, status := range statuses {
		t.Run(status, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != identityStatusResolvePath || r.Method != http.MethodPost {
					t.Errorf("request %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("Authorization") != "Bearer secret" {
					t.Errorf("authorization not sourced from runtime token")
				}
				var body map[string]json.RawMessage
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if len(body) != 2 || string(body["platform_user_id"]) != `"user"` || string(body["tenant_id"]) != `"guild"` {
					t.Errorf("unexpected request body: %s", mustJSON(body))
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"status":"` + status + `","access_request_status":"approved","denial_reason":"policy","retryable":true}`))
			}))
			defer server.Close()
			result, err := NewRuntimeClient(server.URL, time.Second).(*runtimeClient).ResolveIdentityStatus(context.Background(), "secret", IdentityStatusRequest{PlatformUserID: "user", TenantID: "guild"})
			if err != nil || result.Status != status || result.AccessRequestStatus != "approved" || result.DenialReason != "policy" || result.Retryable == nil || !*result.Retryable {
				t.Fatalf("result=%+v err=%v", result, err)
			}
		})
	}
}

func TestResolveIdentityStatusRejectsBadResponsesAndTransport(t *testing.T) {
	catalogHandlerObservedRequest := false
	for name, handler := range map[string]http.HandlerFunc{
		"invalid status": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"status":"made_up"}`)) },
		"malformed":      func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"status":`)) },
		"unknown secret field": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"status":"unlinked","claim_url":"secret"}`))
		},
		"server error": func(w http.ResponseWriter, r *http.Request) {
			catalogHandlerObservedRequest = true
			if r.URL.Path != identityStatusResolvePath || r.Method != http.MethodPost {
				t.Errorf("unexpected request at catalog boundary: %s %s", r.Method, r.URL.Path)
			}
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`sensitive diagnostics`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(handler)
			defer server.Close()
			_, err := NewRuntimeClient(server.URL, time.Second).(*runtimeClient).ResolveIdentityStatus(context.Background(), "token", IdentityStatusRequest{PlatformUserID: "u"})
			if err == nil || strings.Contains(err.Error(), "sensitive") || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsafe or missing error: %v", err)
			}
			var failure *IdentityStatusFailureError
			if !errors.As(err, &failure) {
				t.Fatalf("error is not categorized: %T", err)
			}
			if name == "server error" && (failure.Category != IdentityStatusFailureHTTP || failure.HTTPStatusCode != http.StatusServiceUnavailable) {
				t.Fatalf("HTTP error category/status = %q/%d", failure.Category, failure.HTTPStatusCode)
			}
			if name != "server error" && failure.Category != IdentityStatusFailureResponse {
				t.Fatalf("response error category = %q", failure.Category)
			}
		})
	}
	if !catalogHandlerObservedRequest {
		t.Fatal("non-200 response test did not reach the catalog handler")
	}
	client := NewRuntimeClient("http://127.0.0.1:1", time.Millisecond).(*runtimeClient)
	_, err := client.ResolveIdentityStatus(context.Background(), "token", IdentityStatusRequest{PlatformUserID: "u"})
	var failure *IdentityStatusFailureError
	if !errors.As(err, &failure) || failure.Category != IdentityStatusFailureTransport || failure.HTTPStatusCode != 0 || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("unsafe or uncategorized transport error: %v (%+v)", err, failure)
	}
	if _, err := client.ResolveIdentityStatus(context.Background(), "", IdentityStatusRequest{PlatformUserID: "u"}); !errors.As(err, &failure) || failure.Category != IdentityStatusFailurePreTransport {
		t.Fatalf("expected safe pre-transport classification, got %v", err)
	}
	for _, badURL := range []string{":// invalid", "ftp://catalog.example.test", "https://user:password@catalog.example.test"} {
		badURLClient := NewRuntimeClient(badURL, time.Second).(*runtimeClient)
		if _, err := badURLClient.ResolveIdentityStatus(context.Background(), "token", IdentityStatusRequest{PlatformUserID: "u"}); !errors.As(err, &failure) || failure.Category != IdentityStatusFailurePreTransport {
			t.Fatalf("expected request/config classification for invalid base URL, got %v", err)
		}
	}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
