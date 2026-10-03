package runtime

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockCollectorConfig implements CollectorConfig so tests can exercise the
// flush-client factories without importing the root Config type.
type mockCollectorConfig struct {
	runtimeURL  string
	token       string
	flushURL    string
	flushSecret string
}

func (m mockCollectorConfig) IsRuntime() bool         { return m.token != "" }
func (m mockCollectorConfig) Token() string           { return m.token }
func (m mockCollectorConfig) ControlPlaneURL() string { return m.runtimeURL }
func (m mockCollectorConfig) FlushURL() string        { return m.flushURL }
func (m mockCollectorConfig) FlushSecret() string     { return m.flushSecret }

// TestLifecycleFlushPacesRequestsAndCapturesRetryAfter verifies the lifecycle
// flush client rate-limits itself to one request per 100ms and surfaces the
// Retry-After header from a 429 response.
func TestLifecycleFlushPacesRequestsAndCapturesRetryAfter(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			_, _ = w.Write([]byte(`{"upserted":1}`))
			return
		}
		w.Header().Set("Retry-After", "3")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	client := &lifecycleFlushClient{baseURL: server.URL, path: "/flush", client: server.Client()}
	records := []json.RawMessage{json.RawMessage(`{"event_type":"runtime.started"}`)}
	if _, err := client.FlushLifecycle(context.Background(), records); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err := client.FlushLifecycle(context.Background(), records)
	if err == nil {
		t.Fatal("second flush succeeded, want 429")
	}
	if elapsed := time.Since(started); elapsed < 90*time.Millisecond {
		t.Fatalf("request spacing = %s, want at least 100ms", elapsed)
	}
	delay, ok := lifecycleRetryDelay(err)
	if !ok || delay != 3*time.Second {
		t.Fatalf("retry delay = %s, throttled=%v; want 3s", delay, ok)
	}
}

func TestLifecycleRetryDelayFallbackAndCap(t *testing.T) {
	for _, tc := range []struct {
		name string
		hint time.Duration
		want time.Duration
	}{
		{"missing", 0, time.Second}, {"bounded", 10 * time.Minute, 5 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			delay, ok := lifecycleRetryDelay(&lifecycleFlushHTTPError{statusCode: http.StatusTooManyRequests, retryAfter: tc.hint})
			if !ok || delay != tc.want {
				t.Fatalf("delay=%s throttled=%v; want %s", delay, ok, tc.want)
			}
		})
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

	cfg := mockCollectorConfig{
		runtimeURL:  srv.URL,
		token:       "rt-token",
		flushURL:    "http://internal-abac:8080",
		flushSecret: "internal-secret",
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

		cfg := mockCollectorConfig{flushURL: srv.URL, flushSecret: "legacy-secret"}
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

		cfg := mockCollectorConfig{flushURL: srv.URL}
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

	cfg := mockCollectorConfig{flushURL: srv.URL}
	client := NewABACFlushClientFromConfig(cfg, 5*time.Second)
	_, err := client.Flush(context.Background(), []DecisionEvent{{SpanID: "s-3"}})
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401 error, got %v", err)
	}
}

func TestLifecycleFlushFailureLogsAllowlistedMetadataOnly(t *testing.T) {
	const (
		tokenSentinel   = "synthetic-token-must-not-log"
		requestSentinel = "synthetic-audit-payload-must-not-log"
		bodySentinel    = "synthetic-response-body-must-not-log"
		viaSentinel     = "private-hop-name-must-not-log"
		requestID       = "sensitive-request-id-must-not-log"
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
		w.Header().Set("Server", "envoy")
		w.Header().Set("X-Proxy-Upstream-Status", "409")
		w.Header().Set("X-Envoy-Response-Flags", "NR")
		w.Header().Set("X-Envoy-Upstream-Service-Time", "17")
		w.Header().Set("Via", "1.1 "+viaSentinel)
		w.Header().Set("X-Request-ID", requestID)
		w.Header().Set("Set-Cookie", "session="+tokenSentinel)
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(bodySentinel))
	}))
	defer srv.Close()

	client := NewLifecycleFlushClientFromConfig(mockCollectorConfig{
		runtimeURL: srv.URL,
		token:      tokenSentinel,
	}, 5*time.Second)
	err := func() error {
		_, err := client.FlushLifecycle(context.Background(), []json.RawMessage{json.RawMessage(`{"event_type":"` + requestSentinel + `"}`)})
		return err
	}()
	if err == nil || err.Error() != "lifecycle flush returned status 409" {
		t.Fatalf("FlushLifecycle error = %v, want sanitized 409 status", err)
	}

	var logged strings.Builder
	logger := slog.New(slog.NewJSONHandler(&logged, nil))
	logger.Error("audit collector flush failed", lifecycleFlushLogAttrs(err)...)
	line := logged.String()
	for _, want := range []string{
		`"lifecycle_flush_status":409`,
		`"lifecycle_flush_content_type":"application/problem+json"`,
		`"lifecycle_flush_server":"envoy"`,
		`"lifecycle_flush_upstream_status":"409"`,
		`"lifecycle_flush_proxy_response_flags":"NR"`,
		`"lifecycle_flush_upstream_service_time_ms":"17"`,
	} {
		if !strings.Contains(line, want) {
			t.Errorf("failure log missing %s: %s", want, line)
		}
	}
	for _, forbidden := range []string{tokenSentinel, requestSentinel, bodySentinel, viaSentinel, requestID, "Set-Cookie", "Via"} {
		if strings.Contains(line, forbidden) {
			t.Errorf("failure log contains unapproved data %q: %s", forbidden, line)
		}
	}
}

func TestLifecycleFlushFailureRejectsUnboundedOrUntrustedMetadata(t *testing.T) {
	resp := &http.Response{StatusCode: http.StatusConflict, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "text/plain; secret=must-not-log")
	resp.Header.Set("Server", "internal-gateway.local")
	resp.Header.Set("X-Proxy-Upstream-Status", "409, 500")
	resp.Header.Set("X-Envoy-Response-Flags", "NR:private")
	resp.Header.Set("X-Envoy-Upstream-Service-Time", "17ms")

	err := lifecycleFlushResponseError(resp)
	attrs := lifecycleFlushLogAttrs(err)
	var logged strings.Builder
	slog.New(slog.NewJSONHandler(&logged, nil)).Error("flush failed", attrs...)
	line := logged.String()
	if !strings.Contains(line, `"lifecycle_flush_status":409`) || !strings.Contains(line, `"lifecycle_flush_content_type":"text/plain"`) {
		t.Fatalf("safe status/media type missing from log: %s", line)
	}
	for _, forbidden := range []string{"secret", "internal-gateway", "409, 500", "NR:private", "17ms"} {
		if strings.Contains(line, forbidden) {
			t.Errorf("untrusted metadata %q was logged: %s", forbidden, line)
		}
	}
}
