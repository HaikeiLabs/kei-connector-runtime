package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestEnvConfigLoadsAuditPath verifies the documented KEI_PROXY_AUDIT env var
// populates the audit path for both the authorize subcommand and the collector.
func TestEnvConfigLoadsAuditPath(t *testing.T) {
	t.Setenv("KEI_PROXY_AUDIT", "/var/lib/kei/audit.jsonl")
	cfg := configFromEnv()
	if cfg.AuditPath != "/var/lib/kei/audit.jsonl" {
		t.Fatalf("AuditPath = %q, want /var/lib/kei/audit.jsonl", cfg.AuditPath)
	}
}

// TestFlushClientRuntimeMode verifies a runtime-mode collector flushes to the
// runtime control-plane path and authenticates with the installation token as
// an Authorization bearer, never the internal API secret.
func TestFlushClientRuntimeMode(t *testing.T) {
	var gotPath, gotAuth, gotSecret string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotSecret = r.Header.Get("X-KEI-API-Key")
		_, _ = w.Write([]byte(`{"upserted":1,"received":1}`))
	}))
	defer srv.Close()

	cfg := Config{
		RuntimeControlPlaneURL: srv.URL,
		RuntimeToken:           "rt-token",
		ABACURL:                "http://internal-abac:8080",
		ABACSecret:             "internal-secret",
	}
	client := NewABACFlushClientFromConfig(cfg, 5*time.Second)
	n, err := client.Flush(context.Background(), []DecisionEvent{{SpanID: "s-1", Decision: "allow"}})
	if err != nil {
		t.Fatalf("flush: %v", err)
	}
	if n != 1 {
		t.Fatalf("upserted = %d, want 1", n)
	}
	if gotPath != "/api/v1/runtime/audit/flush" {
		t.Errorf("path = %q, want /api/v1/runtime/audit/flush", gotPath)
	}
	if gotAuth != "Bearer rt-token" {
		t.Errorf("Authorization = %q, want Bearer rt-token", gotAuth)
	}
	if gotSecret != "" {
		t.Errorf("X-KEI-API-Key must never be sent in runtime mode, got %q", gotSecret)
	}
}

// TestFlushClientLegacyMode verifies legacy (harness) mode flushes to the
// internal flush path and carries X-KEI-API-Key only when a secret is
// configured, mirroring the authorize client.
func TestFlushClientLegacyMode(t *testing.T) {
	t.Run("with secret", func(t *testing.T) {
		var gotPath, gotAuth, gotSecret string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			gotAuth = r.Header.Get("Authorization")
			gotSecret = r.Header.Get("X-KEI-API-Key")
			_, _ = w.Write([]byte(`{"upserted":2,"received":2}`))
		}))
		defer srv.Close()

		cfg := Config{ABACURL: srv.URL, ABACSecret: "legacy-secret"}
		client := NewABACFlushClientFromConfig(cfg, 5*time.Second)
		n, err := client.Flush(context.Background(), []DecisionEvent{{SpanID: "s-2", Decision: "deny"}})
		if err != nil {
			t.Fatalf("flush: %v", err)
		}
		if n != 2 {
			t.Fatalf("upserted = %d, want 2", n)
		}
		if gotPath != "/api/v1/audit/flush" {
			t.Errorf("path = %q, want /api/v1/audit/flush", gotPath)
		}
		if gotAuth != "" {
			t.Errorf("Authorization must not be sent in legacy mode, got %q", gotAuth)
		}
		if gotSecret != "legacy-secret" {
			t.Errorf("X-KEI-API-Key = %q, want legacy-secret", gotSecret)
		}
	})

	t.Run("no secret configured", func(t *testing.T) {
		var gotSecret string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotSecret = r.Header.Get("X-KEI-API-Key")
			_, _ = w.Write([]byte(`{"upserted":0,"received":0}`))
		}))
		defer srv.Close()

		cfg := Config{ABACURL: srv.URL}
		client := NewABACFlushClientFromConfig(cfg, 5*time.Second)
		if _, err := client.Flush(context.Background(), nil); err != nil {
			t.Fatalf("flush: %v", err)
		}
		if gotSecret != "" {
			t.Errorf("X-KEI-API-Key = %q, want empty when no secret configured", gotSecret)
		}
	})
}

// TestNewABACFlushClientKeepsPlainLegacyContract verifies the existing
// constructor still targets the internal flush path without credentials.
func TestNewABACFlushClientKeepsPlainLegacyContract(t *testing.T) {
	var gotPath, gotSecret string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotSecret = r.Header.Get("X-KEI-API-Key")
		_, _ = w.Write([]byte(`{"upserted":0,"received":0}`))
	}))
	defer srv.Close()

	client := NewABACFlushClient(srv.URL, 5*time.Second)
	if _, err := client.Flush(context.Background(), nil); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if gotPath != "/api/v1/audit/flush" {
		t.Errorf("path = %q, want /api/v1/audit/flush", gotPath)
	}
	if gotSecret != "" {
		t.Errorf("X-KEI-API-Key = %q, want empty", gotSecret)
	}
}

// TestFlushClientRejectsNonOK guards against silently swallowing a failed
// flush, which would look like success while robbing the spool of its retry.
func TestFlushClientRejectsNonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer srv.Close()

	cfg := Config{ABACURL: srv.URL}
	client := NewABACFlushClientFromConfig(cfg, 5*time.Second)
	_, err := client.Flush(context.Background(), []DecisionEvent{{SpanID: "s-3"}})
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401 error, got %v", err)
	}
}
