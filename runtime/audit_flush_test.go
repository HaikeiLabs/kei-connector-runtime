package runtime

import (
	"context"
	"encoding/json"
	"io"
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
	runtimeURL string
	token      string
}

func (m mockCollectorConfig) IsRuntime() bool         { return m.token != "" }
func (m mockCollectorConfig) Token() string           { return m.token }
func (m mockCollectorConfig) ControlPlaneURL() string { return m.runtimeURL }

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
	var gotBody map[string][]DecisionEvent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotSecret = r.Header.Get("X-KEI-API-Key")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode request: %v", err)
		}
		_, _ = w.Write([]byte(`{"upserted":1,"received":1,"skipped":0}`))
	}))
	defer srv.Close()

	cfg := mockCollectorConfig{
		runtimeURL: srv.URL,
		token:      "rt-token",
	}
	client := NewABACFlushClientFromConfig(cfg, 5*time.Second)
	n, err := client.Flush(context.Background(), []DecisionEvent{{SpanID: "s-1", Decision: "allow"}})
	if err != nil {
		t.Fatalf("flush: %v", err)
	}
	if n != 1 {
		t.Fatalf("upserted = %d, want 1", n)
	}
	if gotPath != "/api/v1/runtime/audit:flush" {
		t.Errorf("path = %q, want /api/v1/runtime/audit:flush", gotPath)
	}
	if len(gotBody["records"]) != 1 || gotBody["records"][0].SpanID != "s-1" || gotBody["records"][0].Decision != "allow" {
		t.Errorf("request body records = %#v, want the one decision event", gotBody["records"])
	}
	if gotAuth != "Bearer rt-token" {
		t.Errorf("Authorization = %q, want Bearer rt-token", gotAuth)
	}
	if gotSecret != "" {
		t.Errorf("X-KEI-API-Key must never be sent in runtime mode, got %q", gotSecret)
	}
}

// TestFlushClientRejectsNonOK guards against silently swallowing a failed
// flush, which would look like success while robbing the spool of its retry.
func TestFlushClientRejectsNonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer srv.Close()

	cfg := mockCollectorConfig{runtimeURL: srv.URL, token: "rt-token"}
	client := NewABACFlushClientFromConfig(cfg, 5*time.Second)
	_, err := client.Flush(context.Background(), []DecisionEvent{{SpanID: "s-3"}})
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401 error, got %v", err)
	}
}

func TestFlushClientAcceptsSkippedAndWarns(t *testing.T) {
	var logs strings.Builder
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"upserted":2,"received":3,"skipped":1}`)
	}))
	defer srv.Close()
	client := NewABACFlushClientFromConfig(mockCollectorConfig{runtimeURL: srv.URL, token: "rt-token"}, time.Second)
	n, err := client.Flush(context.Background(), []DecisionEvent{{SpanID: "s-1"}, {SpanID: "s-2"}, {SpanID: "s-3"}})
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if n != 2 {
		t.Fatalf("upserted = %d, want 2", n)
	}
	if !strings.Contains(logs.String(), `"skipped":1`) {
		t.Fatalf("missing skipped count warning: %s", logs.String())
	}
}

func TestCollectorAdvancesSpoolAfterCatalogSkips(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = io.WriteString(w, `{"upserted":0,"received":1,"skipped":1}`)
	}))
	defer srv.Close()

	path := t.TempDir() + "/decisions.jsonl"
	spool := NewAuditSpool(path, 0)
	if err := spool.Append(EventClassDecision, []byte(`{"span_id":"s-1","decision":"allow"}`)); err != nil {
		t.Fatal(err)
	}
	c := NewCollector(path, NewABACFlushClientFromConfig(mockCollectorConfig{runtimeURL: srv.URL, token: "rt-token"}, time.Second), 100)
	if _, err := c.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if segs, err := c.spool.segments(); err != nil || len(segs) != 0 {
		t.Fatalf("segments after skipped record acknowledgement = %d, err=%v; want drained spool", len(segs), err)
	}
	if _, err := c.Run(context.Background()); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if calls != 1 {
		t.Fatalf("audit requests = %d, want one (stale record must not retry)", calls)
	}
}

func TestFlushClientRejectsPartialOrIncompleteAuditResponse(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"malformed body", `not-json`},
		{"missing canonical count", `{"upserted":1,"received":1}`},
		{"count mismatch", `{"upserted":1,"received":3,"skipped":1}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			client := NewABACFlushClientFromConfig(mockCollectorConfig{runtimeURL: srv.URL, token: "rt-token"}, time.Second)
			if _, err := client.Flush(context.Background(), []DecisionEvent{{SpanID: "s-1"}}); err == nil {
				t.Fatal("Flush succeeded, want response contract error")
			}
		})
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
