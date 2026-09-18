package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiagnoseWhoamiError(t *testing.T) {
	t.Run("extracts WhoamiFailureHTTPStatus from wrapped error", func(t *testing.T) {
		inner := &WhoamiFailure{Category: WhoamiFailureHTTPStatus, StatusCode: http.StatusUnauthorized, Wrapped: fmt.Errorf("runtime identity request returned 401")}
		wrapped := fmt.Errorf("runtime bootstrap failed: %w", inner)
		if got := DiagnoseWhoamiError(wrapped); got != WhoamiFailureHTTPStatus {
			t.Fatalf("DiagnoseWhoamiError() = %d (%s), want %d (http_status)", got, got.String(), WhoamiFailureHTTPStatus)
		}
	})

	t.Run("extracts WhoamiFailureTransport from direct error", func(t *testing.T) {
		inner := &WhoamiFailure{Category: WhoamiFailureTransport, Wrapped: fmt.Errorf("connection refused")}
		if got := DiagnoseWhoamiError(inner); got != WhoamiFailureTransport {
			t.Fatalf("DiagnoseWhoamiError() = %d (%s), want %d (transport)", got, got.String(), WhoamiFailureTransport)
		}
	})

	t.Run("extracts WhoamiFailureDecode from doubly wrapped error", func(t *testing.T) {
		inner := &WhoamiFailure{Category: WhoamiFailureDecode, Wrapped: fmt.Errorf("decode runtime identity response: invalid character")}
		wrapped := fmt.Errorf("runtime bootstrap failed: %w", fmt.Errorf("retry attempt: %w", inner))
		if got := DiagnoseWhoamiError(wrapped); got != WhoamiFailureDecode {
			t.Fatalf("DiagnoseWhoamiError() = %d (%s), want %d (decode)", got, got.String(), WhoamiFailureDecode)
		}
	})

	t.Run("extracts WhoamiFailureIncomplete", func(t *testing.T) {
		inner := &WhoamiFailure{Category: WhoamiFailureIncomplete, Wrapped: fmt.Errorf("runtime identity response is incomplete")}
		if got := DiagnoseWhoamiError(inner); got != WhoamiFailureIncomplete {
			t.Fatalf("DiagnoseWhoamiError() = %d (%s), want %d (incomplete)", got, got.String(), WhoamiFailureIncomplete)
		}
	})

	t.Run("returns WhoamiFailureTransport for plain error", func(t *testing.T) {
		if got := DiagnoseWhoamiError(errors.New("something went wrong")); got != WhoamiFailureTransport {
			t.Fatalf("DiagnoseWhoamiError() = %d (%s), want %d (transport fallback)", got, got.String(), WhoamiFailureTransport)
		}
	})

	t.Run("returns WhoamiFailureTransport for nil", func(t *testing.T) {
		if got := DiagnoseWhoamiError(nil); got != WhoamiFailureTransport {
			t.Fatalf("DiagnoseWhoamiError(nil) = %d (%s), want %d (transport fallback)", got, got.String(), WhoamiFailureTransport)
		}
	})
}

// TestRuntimeBootstrapExitsNonZeroWhenWhoAmIIsRejected exercises the actual
// startup entrypoint (runRuntimeBootstrap) against a real httptest control
// plane that rejects the runtime token with 401. This is the production failure
// shape: a fresh runtime pod whose KEI_RUNTIME_TOKEN does not resolve must fail
// bootstrap (non-zero exit) rather than start the bot unscoped. It complements
// TestRuntimeClientFailsClosedOnRejectedRuntimeToken, which only asserts that
// WhoAmI returns an error, and does not re-test the happy-path bootstrap.
func TestRuntimeBootstrapExitsNonZeroWhenWhoAmIIsRejected(t *testing.T) {
	whoamiCalls := 0
	heartbeatCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/runtime/whoami":
			whoamiCalls++
			w.WriteHeader(http.StatusUnauthorized)
		case "/api/v1/runtime/heartbeat":
			heartbeatCalls++
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected runtime path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := Config{RuntimeToken: "kh_live_rejected_token_1234567890", RuntimeControlPlaneURL: server.URL, RuntimeVersion: "test"}
	var stdout, stderr bytes.Buffer
	code := runRuntimeBootstrap(nil, &stdout, &stderr, cfg, NewRuntimeClient)

	if code == 0 {
		t.Fatalf("bootstrap exit = 0, want non-zero for a rejected runtime token; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "runtime bootstrap failed") {
		t.Fatalf("stderr %q does not name the bootstrap failure", stderr.String())
	}
	if whoamiCalls != 1 {
		t.Fatalf("whoami calls = %d, want 1", whoamiCalls)
	}
	if heartbeatCalls != 0 {
		t.Fatalf("heartbeat calls = %d, want 0 (bootstrap must not heartbeat after a rejected token)", heartbeatCalls)
	}
	if strings.TrimSpace(stdout.String()) != "" {
		t.Fatalf("bootstrap must not emit a scope on failure, got %q", stdout.String())
	}
}
