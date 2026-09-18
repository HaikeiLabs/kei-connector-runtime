package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeFlushClient records the batches it receives so tests can assert on
// batching, ordering, and re-send behavior.
type fakeFlushClient struct {
	batches [][]DecisionEvent
	err     error
	called  chan struct{}
}

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

func (f *fakeFlushClient) Flush(ctx context.Context, records []DecisionEvent) (int, error) {
	if f.err != nil {
		return 0, f.err
	}
	f.batches = append(f.batches, records)
	if f.called != nil {
		select {
		case f.called <- struct{}{}:
		default:
		}
	}
	return len(records), nil
}

func (f *fakeFlushClient) total() int {
	n := 0
	for _, b := range f.batches {
		n += len(b)
	}
	return n
}

func writeJSONL(t *testing.T, path string, events []DecisionEvent) {
	t.Helper()
	var data []byte
	for _, e := range events {
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		data = append(data, append(line, '\n')...)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write jsonl: %v", err)
	}
}

func ev(spanID string) DecisionEvent {
	return DecisionEvent{SpanID: spanID, InvokingSubject: "user-1", AgentID: "agent-1", Framework: "claude", ToolName: "web_search", Decision: "allow"}
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

func TestCollectorPendingStats(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	event := ev("s1")
	event.InvokedAt = time.Now().Add(-2 * time.Minute)
	writeJSONL(t, path, []DecisionEvent{event, ev("s2")})

	c := NewCollector(path, &fakeFlushClient{}, 100)
	pending, oldestAge := c.pendingStats()
	if pending != 2 {
		t.Fatalf("pending = %d, want 2", pending)
	}
	if oldestAge < 100 {
		t.Fatalf("oldest age = %d seconds, want at least 100", oldestAge)
	}

	if _, err := c.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	pending, oldestAge = c.pendingStats()
	if pending != 0 || oldestAge != 0 {
		t.Fatalf("after flush pending=%d age=%d, want 0/0", pending, oldestAge)
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
	writeJSONL(t, path, []DecisionEvent{ev("s1"), ev("s2"), ev("s3"), ev("s4"), ev("s5")})
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
	writeJSONL(t, path, []DecisionEvent{ev("s1"), ev("s2")})

	fake := &fakeFlushClient{}
	c := NewCollector(path, fake, 100)

	if _, err := c.Run(context.Background()); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	// Simulate a crash that lost the state file: the collector re-sends, which
	// is safe because ABAC dedupes on span_id.
	if err := os.Remove(path + ".offset"); err != nil {
		t.Fatalf("remove state: %v", err)
	}
	if _, err := c.Run(context.Background()); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if fake.total() != 4 {
		t.Errorf("total sent = %d, want 4 (re-sent 2 after state loss)", fake.total())
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
	// No state should have been written, so a retry re-sends everything.
	if _, err := os.Stat(path + ".offset"); !os.IsNotExist(err) {
		t.Errorf("state file should not exist after a failed run")
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
