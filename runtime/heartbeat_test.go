package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/policybundlehealth"
)

const heartbeatTestToken = "kh_live_runtime_test_token_1234567890"

// scriptedHeartbeatClient returns results in order and repeats the last one.
// It only implements HeartbeatClient (WhoAmI is not needed for loop tests).
type scriptedHeartbeatClient struct {
	mu      sync.Mutex
	results []error
	reports []HeartbeatReport
}

func (c *scriptedHeartbeatClient) Heartbeat(_ context.Context, _ string, report HeartbeatReport) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reports = append(c.reports, report)
	result := c.results[min(len(c.reports), len(c.results))-1]
	return result
}

func (c *scriptedHeartbeatClient) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.reports)
}

// syncBuffer lets a test read stdout while the loop is still writing it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func heartbeatEvents(t *testing.T, out string) []map[string]any {
	t.Helper()
	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("stdout line is not JSON: %q", line)
		}
		events = append(events, event)
	}
	return events
}

func eventsOf(events []map[string]any, kind string) []map[string]any {
	var matched []map[string]any
	for _, event := range events {
		if event["event"] == kind {
			matched = append(matched, event)
		}
	}
	return matched
}

func statusFailure(status int) error {
	return &HeartbeatFailure{Outcome: ClassifyHeartbeatStatus(status), StatusCode: status, Wrapped: fmt.Errorf("runtime heartbeat returned %d", status)}
}

func testLoop(client HeartbeatClient, out io.Writer) *HeartbeatLoop {
	return &HeartbeatLoop{
		Client:    client,
		Token:     heartbeatTestToken,
		Report:    HeartbeatReport{RuntimeVersion: "test", SchemaVersion: 2},
		Versioned: true,
		Interval:  20 * time.Millisecond,
		Events:    NewHeartbeatEmitter(out, "run-1"),
		Now:       time.Now,
		Jitter:    func(d time.Duration) time.Duration { return d },
	}
}

func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestHeartbeatLoopIncludesPolicyBundleHealthSnapshot(t *testing.T) {
	client := &scriptedHeartbeatClient{results: []error{nil}}
	loop := testLoop(client, io.Discard)
	checked := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	reason := policybundlehealth.ReasonBundleMissing
	loop.PolicyBundle = func() *policybundlehealth.Health {
		return &policybundlehealth.Health{SchemaVersion: 1, State: policybundlehealth.StateCold, CheckedAt: &checked, ReasonCode: &reason}
	}
	if failure := loop.Tick(context.Background()); failure != nil {
		t.Fatal(failure)
	}
	if got := client.reports[0].PolicyBundle; got == nil || got.State != policybundlehealth.StateCold || got.ReportedAt != nil {
		t.Fatalf("policy bundle heartbeat report = %+v", got)
	}
}

func TestHeartbeatLoopRetriesTransientFailureOnceWithinTick(t *testing.T) {
	client := &scriptedHeartbeatClient{results: []error{statusFailure(http.StatusServiceUnavailable), nil}}
	var out syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- testLoop(client, &out).Run(ctx, true) }()
	waitFor(t, "the retried beat", func() bool { return len(eventsOf(heartbeatEvents(t, out.String()), "beat")) > 0 })
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("loop returned %v, want nil after cancellation", err)
	}
	beat := eventsOf(heartbeatEvents(t, out.String()), "beat")[0]
	if beat["outcome"] != "ok" || beat["seq"] != float64(1) {
		t.Fatalf("first beat = %v, want seq 1 recovered to ok by the in-tick retry", beat)
	}
	if client.reports[0].Seq != 1 || client.reports[1].Seq != 1 {
		t.Fatalf("the retry must reuse the tick's seq: %+v", client.reports[:2])
	}
}

func TestHeartbeatLoopKeepsRunningThroughCatalogOutage(t *testing.T) {
	client := &scriptedHeartbeatClient{results: []error{statusFailure(http.StatusBadGateway)}}
	var out syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- testLoop(client, &out).Run(ctx, true) }()
	waitFor(t, "three failed ticks", func() bool { return len(eventsOf(heartbeatEvents(t, out.String()), "beat")) >= 3 })
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("loop exited with %v during a transient outage", err)
	}
	for _, beat := range eventsOf(heartbeatEvents(t, out.String()), "beat") {
		if beat["outcome"] != "catalog_error" || beat["http_status"] != float64(http.StatusBadGateway) {
			t.Fatalf("beat = %v, want catalog_error/502", beat)
		}
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if got := client.reports[4].Counters.BeatsFailedSinceOK; got != 2 {
		t.Fatalf("beats_failed_since_ok on third tick = %d, want 2", got)
	}
}

func TestHeartbeatLoopHonorsRetryAfterWithCap(t *testing.T) {
	for _, tc := range []struct {
		name       string
		retryAfter time.Duration
		wantNext   time.Duration
	}{
		{"within cap", 50 * time.Millisecond, 50 * time.Millisecond},
		{"capped at five intervals", time.Hour, 100 * time.Millisecond},
		{"never shorter than the interval", time.Millisecond, 20 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			throttled := &HeartbeatFailure{Outcome: HeartbeatCatalogBackpressure, StatusCode: http.StatusTooManyRequests, RetryAfter: tc.retryAfter, Wrapped: errors.New("throttled")}
			client := &scriptedHeartbeatClient{results: []error{throttled, nil}}
			var out syncBuffer
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- testLoop(client, &out).Run(ctx, true) }()
			waitFor(t, "the throttled beat", func() bool { return len(eventsOf(heartbeatEvents(t, out.String()), "beat")) > 0 })
			cancel()
			<-done
			beat := eventsOf(heartbeatEvents(t, out.String()), "beat")[0]
			if beat["outcome"] != "catalog_backpressure" || beat["next_in_ms"] != float64(tc.wantNext.Milliseconds()) {
				t.Fatalf("beat = %v, want catalog_backpressure with next_in_ms %d", beat, tc.wantNext.Milliseconds())
			}
			if client.reports[0].Seq != 1 || (len(client.reports) > 1 && client.reports[1].Seq != 2) {
				t.Fatalf("a 429 must not be retried within the tick: %+v", client.reports)
			}
		})
	}
}

func TestHeartbeatLoopStopsOnTerminalCatalogResponses(t *testing.T) {
	for _, tc := range []struct {
		status  int
		outcome HeartbeatOutcome
	}{
		{http.StatusUnauthorized, HeartbeatUnauthorized},
		{http.StatusForbidden, HeartbeatUnauthorized},
		{http.StatusBadRequest, HeartbeatCatalogRejected},
	} {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			client := &scriptedHeartbeatClient{results: []error{statusFailure(tc.status)}}
			var out syncBuffer
			err := testLoop(client, &out).Run(context.Background(), true)
			var failure *HeartbeatFailure
			if !errors.As(err, &failure) || failure.Outcome != tc.outcome {
				t.Fatalf("loop returned %v, want %s", err, tc.outcome)
			}
			if client.calls() != 1 {
				t.Fatalf("heartbeat calls = %d, want 1 (terminal responses are not retried)", client.calls())
			}
		})
	}
}

func TestHeartbeatLoopStopsPromptlyWhenCancelledDuringRetryDelay(t *testing.T) {
	client := &scriptedHeartbeatClient{results: []error{statusFailure(http.StatusServiceUnavailable)}}
	loop := testLoop(client, io.Discard)
	loop.Interval = time.Minute // retry delay is min(5s, interval/4) = 5s
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- loop.Run(ctx, true) }()
	waitFor(t, "the first attempt", func() bool { return client.calls() == 1 })
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("loop returned %v, want nil on cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("loop did not stop within 1s of cancellation")
	}
}

func TestJitterIntervalStaysWithinTenPercent(t *testing.T) {
	for range 1000 {
		if got := JitterInterval(time.Minute); got < 54*time.Second || got > 66*time.Second {
			t.Fatalf("JitterInterval(1m) = %s, outside ±10%%", got)
		}
	}
}

// fakeLifecycleRecorder captures lifecycle records written by the heartbeat loop.
type fakeLifecycleRecorder struct {
	mu      sync.Mutex
	records []LifecycleEvent
}

func (r *fakeLifecycleRecorder) append(e LifecycleEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, e)
	return nil
}

func (r *fakeLifecycleRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.records)
}

func TestHeartbeatLoopWritesLifecycleRecordOnEachTick(t *testing.T) {
	client := &scriptedHeartbeatClient{results: []error{nil}}
	rec := &fakeLifecycleRecorder{}
	var out syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	loop := testLoop(client, &out)
	loop.AppendLifecycle = rec.append
	go func() { done <- loop.Run(ctx, true) }()
	waitFor(t, "two lifecycle records", func() bool { return rec.count() >= 2 })
	cancel()
	<-done

	if n := rec.count(); n < 2 {
		t.Fatalf("got %d lifecycle records, want at least 2", n)
	}
	rec.mu.Lock()
	first := rec.records[0]
	rec.mu.Unlock()

	if first.EventClass != "lifecycle" {
		t.Errorf("event_class = %q, want lifecycle", first.EventClass)
	}
	if first.SchemaVersion != 1 {
		t.Errorf("schema_version = %d, want 1", first.SchemaVersion)
	}
	if first.EventType != "heartbeat" {
		t.Errorf("event_type = %q, want heartbeat", first.EventType)
	}
	if first.Outcome != HeartbeatOK {
		t.Errorf("outcome = %q, want ok", first.Outcome)
	}
	if first.RuntimeVersion != "test" {
		t.Errorf("runtime_version = %q, want test", first.RuntimeVersion)
	}
	if first.Seq != 1 {
		t.Errorf("seq = %d, want 1", first.Seq)
	}
	if first.ObservedAt.IsZero() {
		t.Error("observed_at is zero")
	}
}

func TestHeartbeatLoopWritesLifecycleRecordWithFailureOutcome(t *testing.T) {
	client := &scriptedHeartbeatClient{results: []error{statusFailure(http.StatusBadGateway)}}
	rec := &fakeLifecycleRecorder{}
	var out syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	loop := testLoop(client, &out)
	loop.AppendLifecycle = rec.append
	go func() { done <- loop.Run(ctx, true) }()
	waitFor(t, "one lifecycle record", func() bool { return rec.count() >= 1 })
	cancel()
	<-done

	rec.mu.Lock()
	e := rec.records[0]
	rec.mu.Unlock()

	if e.Outcome != HeartbeatCatalogError {
		t.Errorf("outcome = %q, want catalog_error", e.Outcome)
	}
	if e.Seq != 1 {
		t.Errorf("seq = %d, want 1", e.Seq)
	}
}

func TestHeartbeatLoopDoesNotWriteLifecycleRecordWhenNil(t *testing.T) {
	client := &scriptedHeartbeatClient{results: []error{nil}}
	var out syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	loop := testLoop(client, &out)
	loop.AppendLifecycle = nil
	go func() { done <- loop.Run(ctx, true) }()
	waitFor(t, "one beat event", func() bool {
		return len(eventsOf(heartbeatEvents(t, out.String()), "beat")) > 0
	})
	cancel()
	<-done
}

func TestHeartbeatLoopAppendsLifecycleRecordsToSpool(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")

	client := &scriptedHeartbeatClient{results: []error{nil}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	loop := testLoop(client, io.Discard)
	as := NewAuditSpool(auditPath, 1<<20)
	loop.AppendLifecycle = func(e LifecycleEvent) error {
		data, err := json.Marshal(e)
		if err != nil {
			return err
		}
		return as.Append(EventClassLifecycle, data)
	}
	go func() { done <- loop.Run(ctx, true) }()
	waitFor(t, "one lifecycle record in spool", func() bool {
		data, _ := os.ReadFile(auditPath)
		return len(data) > 0
	})
	cancel()
	<-done

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read spool: %v", err)
	}
	var parsed LifecycleEvent
	if err := json.Unmarshal(bytes.TrimSpace(data), &parsed); err != nil {
		t.Fatalf("unmarshal lifecycle record: %v", err)
	}
	if parsed.EventClass != "lifecycle" {
		t.Errorf("event_class = %q, want lifecycle", parsed.EventClass)
	}
	if parsed.Outcome != HeartbeatOK {
		t.Errorf("outcome = %q, want ok", parsed.Outcome)
	}
}

func TestHeartbeatIdentityAgentFields(t *testing.T) {
	emitted := func(identity *HeartbeatIdentity) map[string]any {
		t.Helper()
		var out bytes.Buffer
		NewHeartbeatEmitter(&out, "run-1").Identity(identity, "1.0.0")
		events := heartbeatEvents(t, out.String())
		if len(events) != 1 {
			t.Fatalf("events = %v, want one identity event", events)
		}
		return events[0]
	}

	t.Run("omitted when whoami has no agents", func(t *testing.T) {
		event := emitted(&HeartbeatIdentity{ID: "installation-1", OrgID: "org-1"})
		for _, key := range []string{"agent_id", "agents", "agents_truncated"} {
			if _, ok := event[key]; ok {
				t.Fatalf("%s must be omitted: %v", key, event)
			}
		}
	})

	t.Run("default taken from agents when agent_id is empty", func(t *testing.T) {
		event := emitted(&HeartbeatIdentity{ID: "installation-1", Agents: []HeartbeatAgent{{AgentID: "agent-1"}, {AgentID: "agent-2", IsDefault: true}}})
		if event["agent_id"] != "agent-2" {
			t.Fatalf("agent_id = %v, want the is_default entry", event["agent_id"])
		}
	})

	t.Run("no default leaves agent_id empty", func(t *testing.T) {
		event := emitted(&HeartbeatIdentity{ID: "installation-1", Agents: []HeartbeatAgent{{AgentID: "agent-1"}}})
		if _, ok := event["agent_id"]; ok {
			t.Fatalf("agent_id must be omitted without a default: %v", event)
		}
		if agents := event["agents"].([]any); len(agents) != 1 {
			t.Fatalf("agents = %v", agents)
		}
	})

	t.Run("huge list is truncated and keeps the default", func(t *testing.T) {
		identity := &HeartbeatIdentity{ID: "installation-1", OrgID: "org-1"}
		for i := 0; i < 500; i++ {
			identity.Agents = append(identity.Agents, HeartbeatAgent{AgentID: fmt.Sprintf("agent-%04d-%s", i, strings.Repeat("x", 24))})
		}
		const defaultID = "agent-the-default"
		identity.Agents = append(identity.Agents, HeartbeatAgent{AgentID: defaultID, IsDefault: true})

		var out bytes.Buffer
		NewHeartbeatEmitter(&out, "run-1").Identity(identity, "1.0.0")
		if line := strings.TrimSuffix(out.String(), "\n"); len(line) == 0 || len(line) >= maxHeartbeatEventBytes {
			t.Fatalf("identity line is %d bytes, want 0 < n < %d", len(line), maxHeartbeatEventBytes)
		}
		event := heartbeatEvents(t, out.String())[0]
		if event["agent_id"] != defaultID || event["agents_truncated"] != true {
			t.Fatalf("event = %v, want the default kept and agents_truncated", event)
		}
		agents := event["agents"].([]any)
		if len(agents) < 2 || len(agents) >= len(identity.Agents) {
			t.Fatalf("kept %d agents, want a truncated but non-trivial list", len(agents))
		}
		if first := agents[0].(map[string]any); first["agent_id"] != "agent-0000-"+strings.Repeat("x", 24) {
			t.Fatalf("truncation must keep whoami order, first = %v", first)
		}
		if last := agents[len(agents)-1].(map[string]any); last["agent_id"] != defaultID || last["is_default"] != true {
			t.Fatalf("default entry must survive truncation, last = %v", last)
		}
	})
}
