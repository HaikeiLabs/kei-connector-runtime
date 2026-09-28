package collector

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// blockingFlusher polls until cancelled and blocks every final flush until its
// deadline, like a flush to an unreachable control plane.
type blockingFlusher struct {
	mu              sync.Mutex
	pollStarted     chan struct{}
	pollStopped     bool
	finalCalls      int
	finalDeadline   time.Duration
	finalBeforeStop bool
}

func (f *blockingFlusher) RunPolling(ctx context.Context, _ time.Duration) error {
	close(f.pollStarted)
	<-ctx.Done()
	f.mu.Lock()
	f.pollStopped = true
	f.mu.Unlock()
	return ctx.Err()
}

func (f *blockingFlusher) Run(ctx context.Context) (int, error) {
	f.mu.Lock()
	f.finalCalls++
	f.finalBeforeStop = !f.pollStopped
	if deadline, ok := ctx.Deadline(); ok {
		f.finalDeadline = time.Until(deadline)
	}
	f.mu.Unlock()
	<-ctx.Done()
	return 0, ctx.Err()
}

func TestServiceStopMakesOneBoundedFinalFlushAfterPolling(t *testing.T) {
	var logs bytes.Buffer
	flusher := &blockingFlusher{pollStarted: make(chan struct{})}
	stop := Service{
		Flusher:           flusher,
		Path:              "/var/lib/kei/audit.jsonl",
		PollInterval:      time.Hour,
		FinalFlushTimeout: 50 * time.Millisecond,
		Logger:            slog.New(slog.NewJSONHandler(&logs, nil)),
	}.Start(context.Background())

	select {
	case <-flusher.pollStarted:
	case <-time.After(time.Second):
		t.Fatal("service did not start polling")
	}
	started := time.Now()
	stopped := make(chan struct{})
	go func() {
		stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("stop exceeded the bounded final flush")
	}
	if elapsed := time.Since(started); elapsed < 40*time.Millisecond {
		t.Fatalf("stop returned after %s, before the final flush finished", elapsed)
	}

	flusher.mu.Lock()
	defer flusher.mu.Unlock()
	if flusher.finalCalls != 1 {
		t.Fatalf("final flush calls = %d, want 1", flusher.finalCalls)
	}
	if flusher.finalBeforeStop {
		t.Fatal("final flush started before polling stopped")
	}
	if flusher.finalDeadline <= 0 || flusher.finalDeadline > 50*time.Millisecond {
		t.Fatalf("final flush deadline = %s, want within 50ms", flusher.finalDeadline)
	}
	out := logs.String()
	for _, want := range []string{"shutdown flush failed; retaining spool", `"path":"/var/lib/kei/audit.jsonl"`, `"records_sent":0`} {
		if !strings.Contains(out, want) {
			t.Fatalf("log %q missing %q", out, want)
		}
	}
}

// countingFlusher returns as soon as it is called.
type countingFlusher struct {
	mu         sync.Mutex
	finalCalls int
	err        error
}

func (f *countingFlusher) RunPolling(ctx context.Context, _ time.Duration) error {
	<-ctx.Done()
	return ctx.Err()
}

func (f *countingFlusher) Run(context.Context) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finalCalls++
	return 3, f.err
}

func TestServiceStopsWithParentContextAndStopIsIdempotent(t *testing.T) {
	var logs bytes.Buffer
	flusher := &countingFlusher{}
	ctx, cancel := context.WithCancel(context.Background())
	stop := Service{
		Flusher:           flusher,
		PollInterval:      time.Hour,
		FinalFlushTimeout: time.Second,
		Logger:            slog.New(slog.NewJSONHandler(&logs, nil)),
	}.Start(ctx)
	cancel()
	stop()
	stop()

	flusher.mu.Lock()
	defer flusher.mu.Unlock()
	if flusher.finalCalls != 1 {
		t.Fatalf("final flush calls = %d, want 1", flusher.finalCalls)
	}
	if logs.Len() != 0 {
		t.Fatalf("successful final flush logged a warning: %s", logs.String())
	}
}

func TestServiceLogsFailedFinalFlush(t *testing.T) {
	var logs bytes.Buffer
	flusher := &countingFlusher{err: errors.New("control plane unavailable")}
	Service{
		Flusher:           flusher,
		Path:              "audit.jsonl",
		PollInterval:      time.Hour,
		FinalFlushTimeout: time.Second,
		Logger:            slog.New(slog.NewJSONHandler(&logs, nil)),
	}.Start(context.Background())()
	if !strings.Contains(logs.String(), `"records_sent":3`) || !strings.Contains(logs.String(), "control plane unavailable") {
		t.Fatalf("failed final flush log = %s", logs.String())
	}
}
