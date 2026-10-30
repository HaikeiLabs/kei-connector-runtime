package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// retryFlushClient accepts remainingFailures failures before succeeding.
type retryFlushClient struct {
	remainingFailures int
	calls             int
	called            chan struct{}
}

func (f *retryFlushClient) Flush(ctx context.Context, records []DecisionEvent) (int, error) {
	f.calls++
	if f.called != nil {
		select {
		case f.called <- struct{}{}:
		default:
		}
	}
	if f.remainingFailures > 0 {
		f.remainingFailures--
		return 0, errors.New("temporary ABAC outage")
	}
	return len(records), nil
}

// total returns the total number of events flushed across all batches.
// fakeFlushClient is defined in spool_test.go.
func (f *fakeFlushClient) total() int {
	n := 0
	for _, b := range f.batches {
		n += len(b)
	}
	return n
}

func TestCollectorFlushesAllPending(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeJSONL(t, path, []DecisionEvent{ev("s1"), ev("s2"), ev("s3")})

	fake := &fakeFlushClient{}
	c := NewCollector(path, fake, 100)

	sent, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sent != 3 {
		t.Errorf("sent = %d, want 3", sent)
	}
	if len(fake.batches) != 1 || len(fake.batches[0]) != 3 {
		t.Errorf("batches = %d, want 1 batch of 3", len(fake.batches))
	}
}

func TestCollectorSuccessfulFlushLogsCountsAndPayloadBytes(t *testing.T) {
	var logs bytes.Buffer
	c := NewCollector(filepath.Join(t.TempDir(), "audit.jsonl"), &fakeFlushClient{}, 100)
	c.LifecycleClient = &fakeLifecycleClient{}
	c.HarnessToolClient = &fakeHarnessToolClient{}
	c.CredentialClient = &fakeCredentialClient{}
	c.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	decision := ev("decision-1")
	lifecycle := json.RawMessage(`{"event_class":"lifecycle","event_type":"heartbeat"}`)
	harnessTool := json.RawMessage(`{"event_class":"harness_tool","tool":"web_search"}`)
	credential := json.RawMessage(`{"event_class":"credential","credential_id":"c1"}`)
	batch := parsedBatch{
		decisions:   []DecisionEvent{decision},
		lifecycle:   []json.RawMessage{lifecycle},
		harnessTool: []json.RawMessage{harnessTool},
		credential:  []json.RawMessage{credential},
	}
	if _, err := c.flushBatch(context.Background(), batch, &skippedRecords{}); err != nil {
		t.Fatalf("flushBatch: %v", err)
	}
	decisionPayload, _ := json.Marshal(map[string][]DecisionEvent{"records": {decision}})
	lifecyclePayload, _ := json.Marshal(map[string][]json.RawMessage{"records": {lifecycle}})
	harnessToolPayload, _ := json.Marshal(map[string][]json.RawMessage{"records": {harnessTool}})
	credentialPayload, _ := json.Marshal(map[string][]json.RawMessage{"records": {credential}})
	for _, want := range [][]byte{
		[]byte(`"event_class":"decision"`),
		[]byte(`"records_sent":1`),
		[]byte(`"payload_bytes":` + strconv.Itoa(len(decisionPayload))),
		[]byte(`"event_class":"lifecycle"`),
		[]byte(`"events_sent":1`),
		[]byte(`"payload_bytes":` + strconv.Itoa(len(lifecyclePayload))),
		[]byte(`"event_class":"harness_tool"`),
		[]byte(`"events_sent":1`),
		[]byte(`"payload_bytes":` + strconv.Itoa(len(harnessToolPayload))),
		[]byte(`"event_class":"credential"`),
		[]byte(`"events_sent":1`),
		[]byte(`"payload_bytes":` + strconv.Itoa(len(credentialPayload))),
	} {
		if !bytes.Contains(logs.Bytes(), want) {
			t.Errorf("successful flush logs missing %s: %s", want, logs.String())
		}
	}
}

func TestCollectorPendingStats(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	event := ev("s1")
	event.InvokedAt = time.Now().Add(-2 * time.Minute)
	writeJSONL(t, path, []DecisionEvent{event, ev("s2")})

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	c := NewCollector(path, &fakeFlushClient{}, 100)
	pendingBytes, pendingFiles, oldestAge := c.pendingStats()
	if pendingBytes != info.Size() || pendingFiles != 1 {
		t.Fatalf("pending = %d bytes in %d files, want %d in 1", pendingBytes, pendingFiles, info.Size())
	}
	if oldestAge < 100 {
		t.Fatalf("oldest age = %d seconds, want at least 100", oldestAge)
	}

	if _, err := c.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	pendingBytes, pendingFiles, oldestAge = c.pendingStats()
	if pendingBytes != 0 || pendingFiles != 0 || oldestAge != 0 {
		t.Fatalf("after flush pending=%d/%d age=%d, want 0/0/0", pendingBytes, pendingFiles, oldestAge)
	}
}

func TestCollectorBatches(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeJSONL(t, path, []DecisionEvent{ev("s1"), ev("s2"), ev("s3"), ev("s4"), ev("s5")})

	fake := &fakeFlushClient{}
	c := NewCollector(path, fake, 2)

	if _, err := c.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(fake.batches) != 3 {
		t.Fatalf("batches = %d, want 3", len(fake.batches))
	}
	wantSizes := []int{2, 2, 1}
	for i, b := range fake.batches {
		if len(b) != wantSizes[i] {
			t.Errorf("batch %d size = %d, want %d", i, len(b), wantSizes[i])
		}
	}
}

func TestCollectorResumable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeJSONL(t, path, []DecisionEvent{ev("s1"), ev("s2"), ev("s3")})

	fake := &fakeFlushClient{}
	c := NewCollector(path, fake, 100)

	if _, err := c.Run(context.Background()); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if fake.total() != 3 {
		t.Fatalf("first run sent %d, want 3", fake.total())
	}

	// Append two more records and re-run: only the new ones are sent.
	for _, e := range []DecisionEvent{ev("s4"), ev("s5")} {
		if err := AppendDecisionEvent(path, 0, e); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if _, err := c.Run(context.Background()); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if fake.total() != 5 {
		t.Errorf("total sent = %d, want 5 (3 + 2 new)", fake.total())
	}
	// The second run should have sent exactly the two new records in one batch.
	last := fake.batches[len(fake.batches)-1]
	if len(last) != 2 || last[0].SpanID != "s4" || last[1].SpanID != "s5" {
		t.Errorf("second run batch = %+v, want [s4 s5]", last)
	}
}

func TestCollectorResendsAfterStateLoss(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeJSONL(t, path, []DecisionEvent{ev("s1"), ev("s2"), ev("s3")})

	// The second batch fails, leaving the segment on disk part-shipped.
	fake := &failAfterFlushClient{okBatches: 1}
	c := NewCollector(path, fake, 2)
	if _, err := c.Run(context.Background()); err == nil {
		t.Fatal("expected the second batch to fail")
	}
	// Simulate a crash that lost the state file: the collector re-sends the
	// whole segment, which is safe because ABAC dedupes on span_id.
	if err := os.Remove(path + ".state"); err != nil {
		t.Fatalf("remove state: %v", err)
	}
	fake.okBatches = -1
	if _, err := c.Run(context.Background()); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if got := fake.spans(); len(got) != 5 || got[2] != "s1" {
		t.Errorf("sent = %v, want [s1 s2 s1 s2 s3] (re-sent after state loss)", got)
	}
}

func TestCollectorNoFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.jsonl")

	fake := &fakeFlushClient{}
	c := NewCollector(path, fake, 100)

	sent, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("Run on missing file: %v", err)
	}
	if sent != 0 {
		t.Errorf("sent = %d, want 0", sent)
	}
}

func TestCollectorSkipsMalformedLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	// One valid, one malformed, one valid.
	data := jsonMarshal(t, ev("s1")) + "\n{not json}\n" + jsonMarshal(t, ev("s2")) + "\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	fake := &fakeFlushClient{}
	c := NewCollector(path, fake, 100)

	sent, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sent != 2 {
		t.Errorf("sent = %d, want 2 (malformed skipped)", sent)
	}
}

func TestCollectorStopsOnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeJSONL(t, path, []DecisionEvent{ev("s1"), ev("s2"), ev("s3")})

	fake := &fakeFlushClient{err: errors.New("abac down")}
	c := NewCollector(path, fake, 100)

	if _, err := c.Run(context.Background()); err == nil {
		t.Fatal("expected error when ABAC is down, got nil")
	}
	// No position should have been recorded, so a retry re-sends everything.
	st, err := readCollectorState(path + ".state")
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if st.LinesSent != 0 {
		t.Errorf("lines_sent = %d after a failed run, want 0", st.LinesSent)
	}
	fake.err = nil
	if sent, err := c.Run(context.Background()); err != nil || sent != 3 {
		t.Fatalf("retry sent %d err %v, want 3 nil", sent, err)
	}
}

func TestCollectorPollingStopsWithContext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeJSONL(t, path, []DecisionEvent{ev("s1")})

	fake := &fakeFlushClient{called: make(chan struct{}, 1)}
	c := NewCollector(path, fake, 100)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.RunPolling(ctx, time.Hour) }()

	select {
	case <-fake.called:
	case <-time.After(time.Second):
		t.Fatal("poller did not perform initial flush")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("RunPolling error = %v, want context.Canceled", err)
	}
}

func TestCollectorPollingLogsReadyOnceWithoutHeartbeats(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	var logs bytes.Buffer
	c := NewCollector(path, &fakeFlushClient{}, 100)
	c.logger = slog.New(slog.NewJSONHandler(&logs, nil))

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := c.RunPolling(ctx, time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("RunPolling error = %v, want context deadline exceeded", err)
	}

	if got := bytes.Count(logs.Bytes(), []byte(`"msg":"audit collector ready"`)); got != 1 {
		t.Fatalf("ready log count = %d, want 1; logs=%s", got, logs.String())
	}
	if bytes.Contains(logs.Bytes(), []byte("audit collector heartbeat")) {
		t.Fatalf("unexpected heartbeat log: %s", logs.String())
	}
}

func TestCollectorPollingRetriesAfterFlushFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeJSONL(t, path, []DecisionEvent{ev("s1")})

	fake := &retryFlushClient{remainingFailures: 1, called: make(chan struct{}, 4)}
	c := NewCollector(path, fake, 100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.RunPolling(ctx, time.Hour) }()

	select {
	case <-fake.called:
	case <-time.After(time.Second):
		t.Fatal("poller did not perform initial flush")
	}
	select {
	case <-fake.called:
	case <-time.After(5 * time.Second):
		t.Fatal("poller did not retry failed flush")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("RunPolling error = %v, want context.Canceled", err)
	}
	if fake.calls < 2 {
		t.Fatalf("flush calls = %d, want at least 2", fake.calls)
	}
}

func jsonMarshal(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(data)
}

// fakeLifecycleClient records lifecycle batches handed to the lifecycle seam.
type fakeLifecycleClient struct {
	records []json.RawMessage
}

func (f *fakeLifecycleClient) FlushLifecycle(ctx context.Context, records []json.RawMessage) (int, error) {
	f.records = append(f.records, records...)
	return len(records), nil
}

// fakeHarnessToolClient records harness_tool batches handed to the seam.
type fakeHarnessToolClient struct {
	records []json.RawMessage
}

func (f *fakeHarnessToolClient) FlushHarnessTool(ctx context.Context, records []json.RawMessage) (HarnessToolFlushResult, error) {
	f.records = append(f.records, records...)
	return HarnessToolFlushResult{Upserted: len(records)}, nil
}

// fakeCredentialClient records credential batches handed to the seam.
type fakeCredentialClient struct {
	records []json.RawMessage
}

func (f *fakeCredentialClient) FlushCredential(ctx context.Context, records []json.RawMessage) (int, error) {
	f.records = append(f.records, records...)
	return len(records), nil
}

type mixedLifecycleClient struct {
	calls    []string
	statuses []int
}

func (f *mixedLifecycleClient) FlushLifecycle(_ context.Context, records []json.RawMessage) (int, error) {
	value := string(records[0])
	f.calls = append(f.calls, value)
	status := http.StatusOK
	if len(f.statuses) > 0 {
		status, f.statuses = f.statuses[0], f.statuses[1:]
	}
	if status == http.StatusTooManyRequests {
		return 0, &lifecycleFlushHTTPError{statusCode: status, retryAfter: time.Second}
	}
	return len(records), nil
}

func TestCollectorRetainsFailedLifecycleBatchAndResumesAfterAcceptedBatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	first := `{"event_class":"lifecycle","event_type":"runtime.started"}`
	second := `{"event_class":"lifecycle","event_type":"runtime.degraded"}`
	if err := os.WriteFile(path, []byte(first+"\n"+second+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fake := &mixedLifecycleClient{statuses: []int{http.StatusOK, http.StatusTooManyRequests, http.StatusOK}}
	collector := NewCollector(path, &retryFlushClient{}, 1)
	collector.LifecycleClient = fake
	if _, err := collector.Run(context.Background()); err == nil {
		t.Fatal("first run succeeded; want synthetic 429")
	}
	state, err := readCollectorState(collector.statePath)
	if err != nil {
		t.Fatal(err)
	}
	if state.LinesSent != 1 {
		t.Fatalf("acknowledged cursor=%d, want 1", state.LinesSent)
	}
	segments, err := collector.spool.segments()
	if err != nil {
		t.Fatal(err)
	}
	if len(segments) != 1 {
		t.Fatalf("pending segments=%d, want failed batch retained", len(segments))
	}
	if _, err := collector.Run(context.Background()); err != nil {
		t.Fatalf("retry run: %v", err)
	}
	if len(fake.calls) != 3 || fake.calls[0] != first || fake.calls[1] != second || fake.calls[2] != second {
		t.Fatalf("flush calls=%q; expected accepted first once and failed second retried", fake.calls)
	}
}

// TestParseBatchSplitsByEventClass pins the same-file contract: legacy lines
// with no event_class and explicit decisions are decisions; lifecycle and
// unknown classes are never decoded as decisions.
func TestParseBatchSplitsByEventClass(t *testing.T) {
	lines := []string{
		`{"span_id":"legacy-1","decision":"allow"}`,
		`{"event_class":"decision","span_id":"dec-1","decision":"deny"}`,
		`{"event_class":"lifecycle","event_type":"runtime.started","outcome":"ok"}`,
		`{"event_class":"harness_tool","tool":"web_search","action":"allow"}`,
		`{"event_class":"credential","credential_id":"c1"}`,
		`{"event_class":"telemetry","span_id":"not-a-decision"}`,
		`{"event_class":"","span_id":"empty-class"}`,
		`{"event_class":7,"span_id":"bad-class-type"}`,
		`{not json}`,
		`["array"]`,
		`null`,
	}
	b := parseBatch(lines)

	if len(b.decisions) != 2 || b.decisions[0].SpanID != "legacy-1" || b.decisions[1].SpanID != "dec-1" {
		t.Fatalf("decisions = %+v, want [legacy-1 dec-1]", b.decisions)
	}
	if len(b.lifecycle) != 1 || !bytes.Contains(b.lifecycle[0], []byte("runtime.started")) {
		t.Fatalf("lifecycle = %q, want the one lifecycle line", b.lifecycle)
	}
	if len(b.harnessTool) != 1 || !bytes.Contains(b.harnessTool[0], []byte("web_search")) {
		t.Fatalf("harnessTool = %q, want the one harness_tool line", b.harnessTool)
	}
	if len(b.credential) != 1 || !bytes.Contains(b.credential[0], []byte("c1")) {
		t.Fatalf("credential = %q, want the one credential line", b.credential)
	}
	if b.unknown != 2 {
		t.Errorf("unknown = %d, want 2 (telemetry and empty class)", b.unknown)
	}
	if b.malformed != 4 {
		t.Errorf("malformed = %d, want 4", b.malformed)
	}
}

// TestCollectorNeverFlushesNonDecisionAsDecision verifies that lifecycle,
// harness_tool, credential, and unknown records are counted and logged as
// skipped while no flush route exists, and that they never reach the decision
// flush endpoint.
func TestCollectorNeverFlushesNonDecisionAsDecision(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	data := jsonMarshal(t, ev("s1")) + "\n" +
		`{"event_class":"lifecycle","event_type":"runtime.degraded"}` + "\n" +
		`{"event_class":"harness_tool","tool":"web_search"}` + "\n" +
		`{"event_class":"credential","credential_id":"c1"}` + "\n" +
		`{"event_class":"mystery"}` + "\n" +
		jsonMarshal(t, ev("s2")) + "\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	var logs bytes.Buffer
	fake := &fakeFlushClient{}
	c := NewCollector(path, fake, 100)
	c.logger = slog.New(slog.NewJSONHandler(&logs, nil))

	sent, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sent != 2 || fake.total() != 2 {
		t.Fatalf("sent = %d flushed = %d, want 2 decisions only", sent, fake.total())
	}
	for _, e := range fake.batches[0] {
		if e.SpanID == "" {
			t.Fatalf("a non-decision record was flushed as a blank decision: %+v", fake.batches[0])
		}
	}
	if !bytes.Contains(logs.Bytes(), []byte("skipped lifecycle records")) {
		t.Errorf("missing lifecycle skip log: %s", logs.String())
	}
	if !bytes.Contains(logs.Bytes(), []byte("skipped harness_tool records")) {
		t.Errorf("missing harness_tool skip log: %s", logs.String())
	}
	if !bytes.Contains(logs.Bytes(), []byte("skipped credential records")) {
		t.Errorf("missing credential skip log: %s", logs.String())
	}
	if !bytes.Contains(logs.Bytes(), []byte("unknown event_class")) {
		t.Errorf("missing unknown class skip log: %s", logs.String())
	}
	if bytes.Contains(logs.Bytes(), []byte("runtime.degraded")) {
		t.Errorf("skip log must carry counts, not record contents: %s", logs.String())
	}
}

// TestCollectorRoutesLifecycleThroughSeam verifies a configured lifecycle
// client receives lifecycle records and the decision endpoint does not.
func TestCollectorRoutesLifecycleThroughSeam(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	data := jsonMarshal(t, ev("s1")) + "\n" + `{"event_class":"lifecycle","event_type":"runtime.started"}` + "\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	fake := &fakeFlushClient{}
	lifecycle := &fakeLifecycleClient{}
	c := NewCollector(path, fake, 100)
	c.LifecycleClient = lifecycle

	if _, err := c.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if fake.total() != 1 || len(lifecycle.records) != 1 {
		t.Fatalf("decisions = %d lifecycle = %d, want 1/1", fake.total(), len(lifecycle.records))
	}
}

func TestCollectorRoutesHarnessToolThroughSeam(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	data := jsonMarshal(t, ev("s1")) + "\n" + `{"event_class":"harness_tool","tool":"web_search"}` + "\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	fake := &fakeFlushClient{}
	harnessTool := &fakeHarnessToolClient{}
	c := NewCollector(path, fake, 100)
	c.HarnessToolClient = harnessTool

	if _, err := c.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if fake.total() != 1 || len(harnessTool.records) != 1 {
		t.Fatalf("decisions = %d harness_tool = %d, want 1/1", fake.total(), len(harnessTool.records))
	}
}

func TestCollectorRoutesCredentialThroughSeam(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	data := jsonMarshal(t, ev("s1")) + "\n" + `{"event_class":"credential","credential_id":"c1"}` + "\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	fake := &fakeFlushClient{}
	credential := &fakeCredentialClient{}
	c := NewCollector(path, fake, 100)
	c.CredentialClient = credential

	if _, err := c.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if fake.total() != 1 || len(credential.records) != 1 {
		t.Fatalf("decisions = %d credential = %d, want 1/1", fake.total(), len(credential.records))
	}
}

// fakeCollectorConfig is a CollectorConfig for the flush-client factories.
type fakeCollectorConfig struct {
	isRuntime    bool
	token        string
	controlPlane string
}

func (f fakeCollectorConfig) IsRuntime() bool         { return f.isRuntime }
func (f fakeCollectorConfig) Token() string           { return f.token }
func (f fakeCollectorConfig) ControlPlaneURL() string { return f.controlPlane }

// TestHarnessToolFlushSendsOnlyFourFields pins the payload boundary: the
// client forwards exactly {tool, skill?, harness_kind, observed_at} and never
// the spool's args_digest / args_ciphertext / tool_input.
func TestHarnessToolFlushSendsOnlyFourFields(t *testing.T) {
	var gotAuth string
	var gotPath string
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"upserted":1}`))
	}))
	defer server.Close()

	client := NewHarnessToolFlushClientFromConfig(fakeCollectorConfig{token: "tok-123", controlPlane: server.URL}, time.Second)
	if client == nil {
		t.Fatal("client is nil")
	}
	raw := json.RawMessage(`{"event_class":"harness_tool","harness_id":"h1","tool":"shell","harness_kind":"claude","args_digest":"sha256:abc","args_ciphertext":"AAAA","tool_input":{"command":"rm -rf"},"observed_at":"2026-10-03T12:00:00Z"}`)
	res, err := client.FlushHarnessTool(context.Background(), []json.RawMessage{raw})
	if err != nil {
		t.Fatalf("FlushHarnessTool: %v", err)
	}
	if n := res.Upserted; n != 1 {
		t.Fatalf("upserted = %d, want 1", n)
	}
	if gotAuth != "Bearer tok-123" {
		t.Fatalf("auth = %q, want Bearer tok-123", gotAuth)
	}
	if gotPath != "/api/v1/runtime/harness-tool-events:batchCreate" {
		t.Fatalf("path = %q", gotPath)
	}
	var envelope struct {
		Events []map[string]any `json:"events"`
	}
	if err := json.Unmarshal(gotBody, &envelope); err != nil {
		t.Fatalf("unmarshal body: %v (body=%s)", err, gotBody)
	}
	if len(envelope.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(envelope.Events))
	}
	ev := envelope.Events[0]
	// skill is optional and omitted when empty, so the event carries at most the
	// four ingest fields; the three required ones must be present.
	if len(ev) > 4 {
		t.Fatalf("event has %d fields, want at most 4: %v", len(ev), ev)
	}
	for _, required := range []string{"tool", "harness_kind", "observed_at"} {
		if _, ok := ev[required]; !ok {
			t.Fatalf("required field %q missing: %v", required, ev)
		}
	}
	for _, forbidden := range []string{"args_digest", "args_ciphertext", "tool_input", "event_class", "harness_id", "schema", "native_decision", "argv0"} {
		if _, ok := ev[forbidden]; ok {
			t.Fatalf("forbidden field %q present: %v", forbidden, ev)
		}
	}
	if ev["tool"] != "shell" || ev["harness_kind"] != "claude_code" || ev["observed_at"] != "2026-10-03T12:00:00Z" {
		t.Fatalf("event = %v, want tool=shell harness_kind=claude_code observed_at=...", ev)
	}
	if _, hasSkill := ev["skill"]; hasSkill {
		t.Fatalf("skill present but must be omitted when empty: %v", ev)
	}
}

// TestHarnessToolFlushCarriesSkill verifies an opencode skill is forwarded.
func TestHarnessToolFlushCarriesSkill(t *testing.T) {
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"upserted":1}`))
	}))
	defer server.Close()

	client := NewHarnessToolFlushClientFromConfig(fakeCollectorConfig{token: "tok", controlPlane: server.URL}, time.Second)
	raw := json.RawMessage(`{"event_class":"harness_tool","tool":"shell","skill":"pdf","harness_kind":"opencode","observed_at":"2026-10-03T12:00:00Z"}`)
	if _, err := client.FlushHarnessTool(context.Background(), []json.RawMessage{raw}); err != nil {
		t.Fatalf("FlushHarnessTool: %v", err)
	}
	var envelope struct {
		Events []map[string]any `json:"events"`
	}
	if err := json.Unmarshal(gotBody, &envelope); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if len(envelope.Events) != 1 || envelope.Events[0]["skill"] != "pdf" || envelope.Events[0]["harness_kind"] != "opencode" {
		t.Fatalf("event = %v, want skill=pdf harness_kind=opencode", envelope.Events)
	}
}

// TestHarnessToolFlushKeepsPiSessionRecord pins the HAI-922 collector half:
// the harness_tool record `kei-proxy hook pi` writes (pseudo tool pi.session,
// harness_kind pi) is a valid tool observation, so the record validation does
// not quarantine it, and canonicalHarnessKind passes "pi" through unchanged.
func TestHarnessToolFlushKeepsPiSessionRecord(t *testing.T) {
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"upserted":1}`))
	}))
	defer server.Close()

	client := NewHarnessToolFlushClientFromConfig(fakeCollectorConfig{token: "tok", controlPlane: server.URL}, time.Second)
	// Exactly the record ReportPermissions marshals for the contract stdin
	// {"session_id":"s1","hook_event_name":"SessionStart","tool_name":"pi.session",
	//  "tool_input":{},"phase":"pre","native_decision":"allow"} (no --harness flag).
	raw := json.RawMessage(`{"schema":"kei.harness-tool-event/v1","event_class":"harness_tool","harness_id":"","harness_kind":"pi","harness_session_id":"s1","phase":"pre","tool":"pi.session","args_digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","native_decision":"allow","observed_at":"2026-10-29T15:40:00Z"}`)
	res, err := client.FlushHarnessTool(context.Background(), []json.RawMessage{raw})
	if err != nil {
		t.Fatalf("FlushHarnessTool: %v", err)
	}
	if n := res.Upserted; n != 1 {
		t.Fatalf("upserted = %d, want 1", n)
	}
	if len(res.Quarantined) != 0 {
		t.Fatalf("quarantined = %v, want none: the pi session record is a valid tool observation", res.Quarantined)
	}
	var envelope struct {
		Events []map[string]any `json:"events"`
	}
	if err := json.Unmarshal(gotBody, &envelope); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if len(envelope.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(envelope.Events))
	}
	ev := envelope.Events[0]
	if ev["tool"] != "pi.session" || ev["harness_kind"] != "pi" || ev["observed_at"] != "2026-10-29T15:40:00Z" {
		t.Fatalf("event = %v, want tool=pi.session harness_kind=pi observed_at=...", ev)
	}
}

// TestHarnessToolFlushBatchesAtMost500 verifies the client splits a large batch
// into chunks of at most 500 events.
func TestHarnessToolFlushBatchesAtMost500(t *testing.T) {
	var mu sync.Mutex
	batchSizes := []int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var envelope struct {
			Events []map[string]any `json:"events"`
		}
		_ = json.Unmarshal(b, &envelope)
		mu.Lock()
		batchSizes = append(batchSizes, len(envelope.Events))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"upserted":` + strconv.Itoa(len(envelope.Events)) + `}`))
	}))
	defer server.Close()

	client := NewHarnessToolFlushClientFromConfig(fakeCollectorConfig{token: "tok", controlPlane: server.URL}, time.Second)
	records := make([]json.RawMessage, 1200)
	for i := range records {
		records[i] = json.RawMessage(fmt.Sprintf(`{"tool":"t%d","harness_kind":"opencode","observed_at":"2026-10-03T12:00:00Z"}`, i))
	}
	res, err := client.FlushHarnessTool(context.Background(), records)
	if err != nil {
		t.Fatalf("FlushHarnessTool: %v", err)
	}
	if n := res.Upserted; n != 1200 {
		t.Fatalf("upserted = %d, want 1200", n)
	}
	want := []int{500, 500, 200}
	if len(batchSizes) != len(want) {
		t.Fatalf("batches = %v, want %v", batchSizes, want)
	}
	for i := range want {
		if batchSizes[i] != want[i] {
			t.Fatalf("batch %d = %d, want %d", i, batchSizes[i], want[i])
		}
	}
}

// TestCanonicalHarnessKind pins the spool->catalog harness_kind mapping.
func TestCanonicalHarnessKind(t *testing.T) {
	cases := map[string]string{
		"claude":   "claude_code",
		"codex":    "codex",
		"opencode": "opencode",
		"cursor":   "cursor",
		"custom":   "custom",
	}
	for in, want := range cases {
		if got := canonicalHarnessKind(in); got != want {
			t.Errorf("canonicalHarnessKind(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestHarnessToolFlushRetriesOnThrottle verifies a 429 with Retry-After is
// surfaced so the collector retains the spool and retries the batch.
func TestHarnessToolFlushRetriesOnThrottle(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		current := requests
		mu.Unlock()
		if current == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"upserted":1}`))
	}))
	defer server.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(path, []byte(`{"event_class":"harness_tool","tool":"shell","harness_kind":"claude","observed_at":"2026-10-03T12:00:00Z"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	collector := NewCollector(path, &fakeFlushClient{}, 100)
	collector.HarnessToolClient = NewHarnessToolFlushClientFromConfig(fakeCollectorConfig{token: "tok", controlPlane: server.URL}, time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- collector.RunPolling(ctx, time.Hour) }()

	deadline := time.Now().Add(8 * time.Second)
	for {
		mu.Lock()
		n := requests
		mu.Unlock()
		if n >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d request(s), want the 429 followed by a retry", n)
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
}

// TestHarnessToolFlushClientNilWithoutToken verifies the factory fails closed
// when no runtime token is configured.
func TestHarnessToolFlushClientNilWithoutToken(t *testing.T) {
	if client := NewHarnessToolFlushClientFromConfig(fakeCollectorConfig{}, time.Second); client != nil {
		t.Fatal("expected a nil client without a token")
	}
}

func TestStartCollectorEmptyPathReturnsNoop(t *testing.T) {
	stop := StartCollector(context.Background(), fakeCollectorConfig{}, "", time.Minute, time.Second)
	stop()
	stop()
}

func TestStartCollectorFlushesRecords(t *testing.T) {
	var (
		mu       sync.Mutex
		flushed  bool
		flushedC = make(chan struct{})
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		flushed = true
		mu.Unlock()
		select {
		case flushedC <- struct{}{}:
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"upserted":1}`))
	}))
	defer server.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeJSONL(t, path, []DecisionEvent{ev("s1")})

	cfg := fakeCollectorConfig{
		isRuntime:    true,
		token:        "test-token",
		controlPlane: server.URL,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := StartCollector(ctx, cfg, path, time.Hour, time.Second)
	defer stop()

	select {
	case <-flushedC:
	case <-time.After(5 * time.Second):
		t.Fatal("collector did not flush before timeout")
	}

	mu.Lock()
	if !flushed {
		t.Fatal("collector did not flush any records")
	}
	mu.Unlock()
}

func TestStartCollectorFlushesOnStop(t *testing.T) {
	var (
		mu       sync.Mutex
		flushed  int
		flushedC = make(chan struct{}, 2)
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		flushed++
		mu.Unlock()
		flushedC <- struct{}{}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"upserted":1}`))
	}))
	defer server.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeJSONL(t, path, []DecisionEvent{ev("s1")})

	cfg := fakeCollectorConfig{
		isRuntime:    true,
		token:        "test-token",
		controlPlane: server.URL,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := StartCollector(ctx, cfg, path, time.Hour, 50*time.Millisecond)

	// Wait for the first poll flush.
	<-flushedC

	// Write another record and stop; the final flush should ship it.
	writeJSONL(t, path, []DecisionEvent{ev("s2")})

	stop()

	select {
	case <-flushedC:
	case <-time.After(time.Second):
		t.Fatal("collector did not flush the final batch before stop deadline")
	}

	mu.Lock()
	if flushed < 2 {
		t.Fatalf("collector flushed %d time(s), want at least 2", flushed)
	}
	mu.Unlock()
}

// poisonCatalog is a fake harness-tool-events:batchCreate that rejects any
// batch holding a tool named poisonTool, the way the catalog validates the
// whole batch before writing: one bad event is a 400 and nothing is stored.
type poisonCatalog struct {
	mu      sync.Mutex
	shipped []string
	status  int
}

const poisonTool = "poison-tool-name"

func (p *poisonCatalog) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Events []harnessToolIngestEvent `json:"events"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	w.Header().Set("Content-Type", "application/json")
	if p.status != 0 {
		w.WriteHeader(p.status)
		_, _ = w.Write([]byte(`{"error":{"code":401,"status":"UNAUTHENTICATED","message":"invalid runtime token"}}`))
		return
	}
	for _, e := range req.Events {
		if e.Tool == poisonTool || strings.TrimSpace(e.Tool) == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"code":400,"status":"INVALID_ARGUMENT","message":"harness_kind_invalid","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"INVALID_ARGUMENT","domain":"kei"}]}}`))
			return
		}
	}
	p.mu.Lock()
	for _, e := range req.Events {
		p.shipped = append(p.shipped, e.Tool)
	}
	p.mu.Unlock()
	_, _ = w.Write([]byte(`{"upserted":` + strconv.Itoa(len(req.Events)) + `}`))
}

func writeHarnessToolSpool(t *testing.T, tools ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "harness-tool.jsonl")
	var b strings.Builder
	for _, tool := range tools {
		b.WriteString(`{"event_class":"harness_tool","phase":"decision","tool":"` + tool + `","harness_kind":"claude","args_digest":"sha256:abc","observed_at":"2026-10-12T17:52:00.123456789Z"}` + "\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestCollectorQuarantinesRecordTheCatalogRejects pins the unwedge: one record
// the catalog 400s must not hold back the rest. The good records ship, the
// rejected one and the tool-less one are quarantined and counted as loss by
// reason code, the spool advances, and the log names the catalog's reason but
// never the record's contents.
func TestCollectorQuarantinesRecordTheCatalogRejects(t *testing.T) {
	catalog := &poisonCatalog{}
	server := httptest.NewServer(catalog)
	defer server.Close()

	path := writeHarnessToolSpool(t, "Read", "shell", poisonTool, "", "Edit", "Grep")
	var logs bytes.Buffer
	c := NewCollector(path, &fakeFlushClient{}, 100)
	c.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	c.HarnessToolClient = NewHarnessToolFlushClientFromConfig(fakeCollectorConfig{token: "tok", controlPlane: server.URL}, time.Second)

	if _, err := c.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v (logs=%s)", err, logs.String())
	}
	catalog.mu.Lock()
	shipped := strings.Join(catalog.shipped, ",")
	catalog.mu.Unlock()
	if shipped != "Read,shell,Edit,Grep" {
		t.Fatalf("shipped = %q, want Read,shell,Edit,Grep", shipped)
	}
	if _, files, _ := c.pendingStats(); files != 0 {
		t.Fatalf("pending files = %d, want 0: the spool must advance past the rejected record", files)
	}
	st, err := readCollectorState(c.statePath)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{"catalog_rejected": 1, "tool_missing": 1}
	if fmt.Sprint(st.HarnessToolQuarantined) != fmt.Sprint(want) {
		t.Fatalf("quarantined = %v, want %v", st.HarnessToolQuarantined, want)
	}
	out := logs.String()
	for _, needle := range []string{"quarantined", "catalog_rejected", "harness_kind_invalid", "INVALID_ARGUMENT"} {
		if !strings.Contains(out, needle) {
			t.Fatalf("log missing %q: %s", needle, out)
		}
	}
	if strings.Contains(out, poisonTool) || strings.Contains(out, "sha256:abc") {
		t.Fatalf("log leaks record contents: %s", out)
	}
}

// TestCollectorRetainsSpoolOnUnauthorized verifies that only a record
// rejection is quarantined: a 401 is the installation's problem, not the
// record's, so the spool is retained and nothing is dropped.
func TestCollectorRetainsSpoolOnUnauthorized(t *testing.T) {
	catalog := &poisonCatalog{status: http.StatusUnauthorized}
	server := httptest.NewServer(catalog)
	defer server.Close()

	path := writeHarnessToolSpool(t, "Read", "Edit")
	c := NewCollector(path, &fakeFlushClient{}, 100)
	c.logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	c.HarnessToolClient = NewHarnessToolFlushClientFromConfig(fakeCollectorConfig{token: "tok", controlPlane: server.URL}, time.Second)

	_, err := c.Run(context.Background())
	if err == nil {
		t.Fatal("Run succeeded, want the 401 surfaced")
	}
	if !strings.Contains(err.Error(), "status 401") || !strings.Contains(err.Error(), "invalid runtime token") {
		t.Fatalf("error = %v, want status 401 with the catalog's message", err)
	}
	if _, files, _ := c.pendingStats(); files == 0 {
		t.Fatal("spool was dropped on a 401")
	}
	st, _ := readCollectorState(c.statePath)
	if len(st.HarnessToolQuarantined) != 0 {
		t.Fatalf("quarantined on a 401: %v", st.HarnessToolQuarantined)
	}
}
