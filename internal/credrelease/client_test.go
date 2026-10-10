package credrelease

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestResolveErrorCarriesSafeRequestDiagnostics(t *testing.T) {
	var outboundRequestID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outboundRequestID = r.Header.Get("X-Request-ID")
		w.Header().Set("X-Request-ID", "identity-request-123")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "runtime-token-never-log", time.Second)
	_, err := client.resolve(context.Background(), "subject-token-never-log", nil)
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("error = %v, want ErrUnauthenticated", err)
	}
	if _, parseErr := uuid.Parse(outboundRequestID); parseErr != nil {
		t.Fatalf("outbound X-Request-ID = %q, want UUID: %v", outboundRequestID, parseErr)
	}
	host, requestID, responseRequestID, ok := RequestDiagnostics(err)
	if !ok || host != "127.0.0.1" || requestID != outboundRequestID || responseRequestID != "identity-request-123" {
		t.Fatalf("diagnostics = (%q, %q, %q, %t)", host, requestID, responseRequestID, ok)
	}
	if strings.Contains(err.Error(), "runtime-token-never-log") || strings.Contains(err.Error(), "subject-token-never-log") {
		t.Fatalf("error exposed credential material: %v", err)
	}
}

func TestResolveDoesNotFollowRedirects(t *testing.T) {
	var destinationCalls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		destinationCalls.Add(1)
	}))
	defer destination.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer runtime-token" || r.Header.Get("X-Kei-Subject-Token") != "subject-token" {
			t.Errorf("I11 credentials missing from original request")
		}
		w.Header().Set("X-Request-ID", "origin-request-456")
		http.Redirect(w, r, destination.URL+ResolvePath, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	client := NewClient(origin.URL, "runtime-token", time.Second)
	_, err := client.resolve(context.Background(), "subject-token", nil)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v, want ErrUnavailable for redirect", err)
	}
	if destinationCalls.Load() != 0 {
		t.Fatalf("redirect destination called %d times, want 0", destinationCalls.Load())
	}
	host, _, responseRequestID, ok := RequestDiagnostics(err)
	if !ok || host != "127.0.0.1" || responseRequestID != "origin-request-456" {
		t.Fatalf("diagnostics = (%q, %q, %t)", host, responseRequestID, ok)
	}
}
