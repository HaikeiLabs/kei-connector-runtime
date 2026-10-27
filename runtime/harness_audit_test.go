package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// spoolHarnessLine is a hook spool record as kei-proxy hook writes it, plus a
// tool_input field the collector must never forward.
const spoolHarnessLine = `{"schema":"kei.harness-tool-event/v1","event_class":"harness_tool","harness_id":"agent-7","harness_kind":"claude","harness_registered":false,"harness_session_id":"sess-1","tool_use_id":"tu-1","phase":"pre","tool":"shell","skill":"pdf","args_digest":"hmac-sha256:abc","digest_key_id":"dk-1","args_ciphertext":"YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBk+/=","recipient_key_ids":["rk-1","rk-2"],"native_decision":"allow","argv0":"curl","tool_input":{"command":"curl -H token:s3cr3t"},"observed_at":"2026-10-06T12:00:00Z"}`

var harnessAuditContractFields = map[string]bool{
	"event_class": true, "harness_agent_id": true, "harness_kind": true, "tool": true, "skill": true,
	"phase": true, "native_decision": true, "args_digest": true, "digest_key_id": true,
	"args_ciphertext": true, "recipient_key_ids": true, "harness_session_id": true,
	"tool_use_id": true, "observed_at": true,
}

type recordedRequest struct {
	path string
	auth string
	body []byte
}

type recordingServer struct {
	mu       sync.Mutex
	requests []recordedRequest
	status   func(path string) int
}

func (s *recordingServer) handler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.requests = append(s.requests, recordedRequest{path: r.URL.Path, auth: r.Header.Get("Authorization"), body: body})
	s.mu.Unlock()
	if s.status != nil {
		if code := s.status(r.URL.Path); code != http.StatusOK {
			w.WriteHeader(code)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"upserted":1}`))
}

func (s *recordingServer) bodiesFor(path string) [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out [][]byte
	for _, r := range s.requests {
		if r.path == path {
			out = append(out, r.body)
		}
	}
	return out
}

func decodeAuditRecords(t *testing.T, body []byte) []map[string]any {
	t.Helper()
	var envelope map[string][]map[string]any
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode body: %v (%s)", err, body)
	}
	if len(envelope) != 1 || envelope["records"] == nil {
		t.Fatalf("envelope keys = %v, want only records", envelope)
	}
	return envelope["records"]
}

func TestHarnessAuditFlushSendsOnlyContractFields(t *testing.T) {
	srv := &recordingServer{}
	server := httptest.NewServer(http.HandlerFunc(srv.handler))
	defer server.Close()

	client := NewHarnessAuditFlushClientFromConfig(fakeCollectorConfig{token: "tok-123", controlPlane: server.URL}, time.Second)
	if _, err := client.FlushHarnessAudit(context.Background(), []json.RawMessage{json.RawMessage(spoolHarnessLine)}); err != nil {
		t.Fatalf("FlushHarnessAudit: %v", err)
	}
	if len(srv.requests) != 1 || srv.requests[0].path != "/api/v1/runtime/audit:flush" || srv.requests[0].auth != "Bearer tok-123" {
		t.Fatalf("requests = %+v", srv.requests)
	}
	records := decodeAuditRecords(t, srv.requests[0].body)
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	rec := records[0]
	var keys []string
	for k := range rec {
		keys = append(keys, k)
		if !harnessAuditContractFields[k] {
			t.Errorf("non-contract field %q forwarded", k)
		}
	}
	sort.Strings(keys)
	if len(keys) != len(harnessAuditContractFields) {
		t.Fatalf("fields = %v, want every contract field", keys)
	}
	want := map[string]any{
		"event_class": "harness_tool", "harness_agent_id": "agent-7", "harness_kind": "claude",
		"tool": "shell", "skill": "pdf", "phase": "pre", "native_decision": "allow",
		"args_digest": "hmac-sha256:abc", "digest_key_id": "dk-1", "harness_session_id": "sess-1",
		"tool_use_id": "tu-1", "observed_at": "2026-10-06T12:00:00Z",
	}
	for k, v := range want {
		if rec[k] != v {
			t.Errorf("%s = %v, want %v", k, rec[k], v)
		}
	}
	if ids, _ := rec["recipient_key_ids"].([]any); len(ids) != 2 || ids[0] != "rk-1" || ids[1] != "rk-2" {
		t.Errorf("recipient_key_ids = %v", rec["recipient_key_ids"])
	}
}

func TestHarnessAuditFlushPassesCiphertextThroughUntouched(t *testing.T) {
	srv := &recordingServer{}
	server := httptest.NewServer(http.HandlerFunc(srv.handler))
	defer server.Close()

	var spooled struct {
		ArgsCiphertext string `json:"args_ciphertext"`
	}
	if err := json.Unmarshal([]byte(spoolHarnessLine), &spooled); err != nil {
		t.Fatal(err)
	}
	client := NewHarnessAuditFlushClientFromConfig(fakeCollectorConfig{token: "tok", controlPlane: server.URL}, time.Second)
	if _, err := client.FlushHarnessAudit(context.Background(), []json.RawMessage{json.RawMessage(spoolHarnessLine)}); err != nil {
		t.Fatal(err)
	}
	if got := decodeAuditRecords(t, srv.requests[0].body)[0]["args_ciphertext"]; got != spooled.ArgsCiphertext {
		t.Fatalf("args_ciphertext = %q, want byte-identical %q", got, spooled.ArgsCiphertext)
	}
}

func TestHarnessAuditFlushDropsRecordsMissingContractFields(t *testing.T) {
	srv := &recordingServer{}
	server := httptest.NewServer(http.HandlerFunc(srv.handler))
	defer server.Close()

	client := NewHarnessAuditFlushClientFromConfig(fakeCollectorConfig{token: "tok", controlPlane: server.URL}, time.Second)
	bad := []json.RawMessage{
		json.RawMessage(`{"event_class":"harness_tool","tool":"web_search"}`),
		json.RawMessage(strings.Replace(spoolHarnessLine, `"harness_kind":"claude"`, `"harness_kind":"warp"`, 1)),
		json.RawMessage(strings.Replace(spoolHarnessLine, `"args_digest":"hmac-sha256:abc"`, `"args_digest":""`, 1)),
		json.RawMessage(`not json`),
	}
	if _, err := client.FlushHarnessAudit(context.Background(), append(bad, json.RawMessage(spoolHarnessLine))); err != nil {
		t.Fatal(err)
	}
	if records := decodeAuditRecords(t, srv.requests[0].body); len(records) != 1 {
		t.Fatalf("records = %d, want only the valid one", len(records))
	}
}

// TestHarnessAuditFlushShipsCursorKinds pins cursor as a forwardable audit
// kind, like claude, codex and opencode.
func TestHarnessAuditFlushShipsCursorKinds(t *testing.T) {
	srv := &recordingServer{}
	server := httptest.NewServer(http.HandlerFunc(srv.handler))
	defer server.Close()

	client := NewHarnessAuditFlushClientFromConfig(fakeCollectorConfig{token: "tok", controlPlane: server.URL}, time.Second)
	line := strings.Replace(spoolHarnessLine, `"harness_kind":"claude"`, `"harness_kind":"cursor"`, 1)
	if _, err := client.FlushHarnessAudit(context.Background(), []json.RawMessage{json.RawMessage(line)}); err != nil {
		t.Fatal(err)
	}
	if len(srv.requests) != 1 {
		t.Fatalf("audit requests = %d, want the cursor record forwarded", len(srv.requests))
	}
	records := decodeAuditRecords(t, srv.requests[0].body)
	if len(records) != 1 || records[0]["harness_kind"] != "cursor" {
		t.Fatalf("records = %v, want one cursor record", records)
	}
}

func TestHarnessAuditFlushBatchesAtMost100(t *testing.T) {
	srv := &recordingServer{}
	server := httptest.NewServer(http.HandlerFunc(srv.handler))
	defer server.Close()

	client := NewHarnessAuditFlushClientFromConfig(fakeCollectorConfig{token: "tok", controlPlane: server.URL}, time.Second)
	records := make([]json.RawMessage, 250)
	for i := range records {
		records[i] = json.RawMessage(strings.Replace(spoolHarnessLine, `"tu-1"`, fmt.Sprintf(`"tu-%d"`, i), 1))
	}
	if _, err := client.FlushHarnessAudit(context.Background(), records); err != nil {
		t.Fatal(err)
	}
	var sizes []int
	for _, body := range srv.bodiesFor("/api/v1/runtime/audit:flush") {
		sizes = append(sizes, len(decodeAuditRecords(t, body)))
	}
	if fmt.Sprint(sizes) != "[100 100 50]" {
		t.Fatalf("batch sizes = %v, want [100 100 50]", sizes)
	}
}

func TestHarnessAuditFlushThrottleIsRetryable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := NewHarnessAuditFlushClientFromConfig(fakeCollectorConfig{token: "tok", controlPlane: server.URL}, time.Second)
	_, err := client.FlushHarnessAudit(context.Background(), []json.RawMessage{json.RawMessage(spoolHarnessLine)})
	if delay, ok := lifecycleRetryDelay(err); !ok || delay != 7*time.Second {
		t.Fatalf("retry delay = %v ok=%v err=%v", delay, ok, err)
	}
	var httpErr *harnessAuditFlushHTTPError
	if !errors.As(err, &httpErr) || httpErr.statusCode != http.StatusTooManyRequests {
		t.Fatalf("err = %v", err)
	}
}

func TestHarnessAuditFlushClientNilWithoutToken(t *testing.T) {
	if NewHarnessAuditFlushClientFromConfig(fakeCollectorConfig{controlPlane: "https://example.test"}, time.Second) != nil {
		t.Fatal("client without a runtime token")
	}
}

// TestCollectorShipsHarnessToolToIngestAndAudit runs the collector end to end:
// harness_tool records go to both the skill-tool-mappings ingest and
// audit:flush, no request body ever carries tool_input, and a failed
// audit:flush keeps the cursor so the next run resends the batch.
func TestCollectorShipsHarnessToolToIngestAndAudit(t *testing.T) {
	failAudit := true
	var mu sync.Mutex
	srv := &recordingServer{status: func(path string) int {
		mu.Lock()
		defer mu.Unlock()
		if path == "/api/v1/runtime/audit:flush" && failAudit {
			return http.StatusInternalServerError
		}
		return http.StatusOK
	}}
	server := httptest.NewServer(http.HandlerFunc(srv.handler))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "audit", "harness-tool.jsonl")
	spool := NewPrivateAuditSpool(path, 0)
	for range 3 {
		if err := spool.Append(EventClassHarnessTool, []byte(spoolHarnessLine)); err != nil {
			t.Fatal(err)
		}
	}
	cfg := fakeCollectorConfig{token: "tok", controlPlane: server.URL}
	c := NewCollector(path, NewABACFlushClientFromConfig(cfg, time.Second), 100)
	c.HarnessToolClient = NewHarnessToolFlushClientFromConfig(cfg, time.Second)
	c.HarnessAuditClient = NewHarnessAuditFlushClientFromConfig(cfg, time.Second)

	if _, err := c.Run(context.Background()); err == nil {
		t.Fatal("audit:flush 500 did not fail the run")
	}
	mu.Lock()
	failAudit = false
	mu.Unlock()
	if _, err := c.Run(context.Background()); err != nil {
		t.Fatalf("retry run: %v", err)
	}

	audit := srv.bodiesFor("/api/v1/runtime/audit:flush")
	if len(audit) != 2 || len(decodeAuditRecords(t, audit[1])) != 3 {
		t.Fatalf("audit:flush requests = %d, want failed + resent batch of 3", len(audit))
	}
	if ingest := srv.bodiesFor("/api/v1/runtime/harness-tool-events:batchCreate"); len(ingest) == 0 {
		t.Fatal("skill-tool-mappings ingest no longer receives harness_tool records")
	}
	for _, r := range srv.requests {
		for _, forbidden := range []string{"tool_input", "s3cr3t", "argv0", "curl -H"} {
			if bytes.Contains(r.body, []byte(forbidden)) {
				t.Fatalf("%s body carries %q: %s", r.path, forbidden, r.body)
			}
		}
	}
	if _, err := c.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(srv.bodiesFor("/api/v1/runtime/audit:flush")); n != 2 {
		t.Fatalf("shipped records resent after success: %d audit requests", n)
	}
	if fi, err := os.Stat(filepath.Dir(path)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("private spool dir mode = %v err=%v", fi.Mode().Perm(), err)
	}
}

func TestResolveAuditPathDefaultsToHarnessSpool(t *testing.T) {
	if got := ResolveAuditPath("/var/log/kei/audit.jsonl", "/state"); got != "/var/log/kei/audit.jsonl" {
		t.Fatalf("explicit path = %q", got)
	}
	if got := ResolveAuditPath("", "/state"); got != filepath.Join("/state", "audit", "harness-tool.jsonl") {
		t.Fatalf("default path = %q", got)
	}
	if got := ResolveAuditPath("", ""); got != "" {
		t.Fatalf("no state dir = %q", got)
	}
}
