package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeFlushClient records the batches it receives so tests can assert on
// batching, ordering, and re-send behavior.
type fakeFlushClient struct {
	batches [][]DecisionEvent
	err     error
	called  chan struct{}
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

// failAfterFlushClient accepts okBatches batches and then fails, simulating a
// collector crash or outage part way through a segment. -1 never fails.
type failAfterFlushClient struct {
	okBatches int
	batches   [][]DecisionEvent
}

func (f *failAfterFlushClient) Flush(ctx context.Context, records []DecisionEvent) (int, error) {
	if f.okBatches == 0 {
		return 0, errors.New("abac down")
	}
	if f.okBatches > 0 {
		f.okBatches--
	}
	f.batches = append(f.batches, records)
	return len(records), nil
}

func (f *failAfterFlushClient) spans() []string {
	var out []string
	for _, b := range f.batches {
		for _, e := range b {
			out = append(out, e.SpanID)
		}
	}
	return out
}

// sizedRecord builds a JSON record with the given leading fields whose line,
// including its newline, is exactly size bytes.
func sizedRecord(t *testing.T, fields string, size int) []byte {
	t.Helper()
	base := fmt.Sprintf(`{%s,"pad":""}`, fields)
	pad := size - 1 - len(base)
	if pad < 0 {
		t.Fatalf("record %s does not fit in %d bytes", base, size)
	}
	return []byte(fmt.Sprintf(`{%s,"pad":"%s"}`, fields, strings.Repeat("x", pad)))
}

func decisionRecord(t *testing.T, span string, size int) []byte {
	return sizedRecord(t, fmt.Sprintf(`"span_id":%q,"decision":"allow"`, span), size)
}

func lifecycleRecord(t *testing.T, size int) []byte {
	return sizedRecord(t, `"event_class":"lifecycle"`, size)
}

func harnessToolRecord(t *testing.T, size int) []byte {
	return sizedRecord(t, `"event_class":"harness_tool"`, size)
}

func credentialRecord(t *testing.T, size int) []byte {
	return sizedRecord(t, `"event_class":"credential"`, size)
}

// spoolTotal measures the whole spool under its lock, so it is consistent
// with concurrent writers.
func spoolTotal(t *testing.T, s *AuditSpool) int64 {
	t.Helper()
	var total int64
	err := s.withLock(func() error {
		segs, err := s.segments()
		if err != nil {
			return err
		}
		for _, seg := range segs {
			total += seg.size
		}
		size, err := fileSize(s.path)
		total += size
		return err
	})
	if err != nil {
		t.Fatalf("measure spool: %v", err)
	}
	return total
}

// spoolLines returns every line left in the spool, oldest first.
func spoolLines(t *testing.T, s *AuditSpool) []string {
	t.Helper()
	segs, err := s.segments()
	if err != nil {
		t.Fatalf("segments: %v", err)
	}
	var lines []string
	for _, p := range append(segPaths(segs), s.path) {
		data, err := os.ReadFile(p)
		if err != nil && !os.IsNotExist(err) {
			t.Fatalf("read %s: %v", p, err)
		}
		for _, l := range strings.Split(string(data), "\n") {
			if l != "" {
				lines = append(lines, l)
			}
		}
	}
	return lines
}

func segPaths(segs []spoolSegment) []string {
	var out []string
	for _, seg := range segs {
		out = append(out, seg.path)
	}
	return out
}

func ev(spanID string) DecisionEvent {
	return DecisionEvent{SpanID: spanID, InvokingSubject: "user-1", AgentID: "agent-1", Framework: "claude", ToolName: "web_search", Decision: "allow"}
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

func TestSpoolRotatesAtSegmentSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s := NewAuditSpool(path, 1000) // segments of 100 bytes

	for i := 0; i < 5; i++ {
		if err := s.Append(EventClassDecision, decisionRecord(t, fmt.Sprintf("s%d", i), 50)); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	segs, err := s.segments()
	if err != nil {
		t.Fatalf("segments: %v", err)
	}
	// Two 50-byte records fill a 100-byte segment; the fifth is active.
	if len(segs) != 2 || segs[0].seq != 1 || segs[1].seq != 2 {
		t.Fatalf("segments = %+v, want seq 1 and 2", segs)
	}
	for _, seg := range segs {
		if seg.size != 100 {
			t.Errorf("segment %d size = %d, want 100", seg.seq, seg.size)
		}
	}
	if filepath.Base(segs[0].path) != "audit.jsonl.0000000001" {
		t.Errorf("segment name = %s, want zero-padded sequence", filepath.Base(segs[0].path))
	}
	if size, _ := fileSize(path); size != 50 {
		t.Errorf("active size = %d, want 50", size)
	}
	if got := s.readMeta().NextSeq; got != 3 {
		t.Errorf("next_seq = %d, want 3", got)
	}
}

// TestSpoolEvictsOldestUnsentAndCountsLoss fills the spool past its cap and
// checks the oldest records go, the newest stay, the cap holds, and every
// dropped record is counted and reported by the collector exactly once.
func TestSpoolEvictsOldestUnsentAndCountsLoss(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s := NewAuditSpool(path, 1000)

	const n = 30
	for i := 0; i < n; i++ {
		if err := s.Append(EventClassDecision, decisionRecord(t, fmt.Sprintf("s%02d", i), 50)); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		if total := spoolTotal(t, s); total > 1000 {
			t.Fatalf("after append %d spool is %d bytes, cap 1000", i, total)
		}
	}

	lines := spoolLines(t, s)
	loss := s.readMeta().Loss
	if int64(len(lines))+loss.EvictedRecords != n {
		t.Fatalf("kept %d + evicted %d != appended %d", len(lines), loss.EvictedRecords, n)
	}
	if loss.EvictedSegments == 0 || loss.EvictedBytes != loss.EvictedRecords*50 {
		t.Fatalf("loss = %+v, want whole 50-byte records counted", loss)
	}
	if !strings.Contains(lines[len(lines)-1], `"s29"`) {
		t.Errorf("newest record was not kept: last line %s", lines[len(lines)-1])
	}
	if strings.Contains(strings.Join(lines, "\n"), `"s00"`) {
		t.Errorf("oldest record survived eviction")
	}

	var logs bytes.Buffer
	c := NewCollector(path, &fakeFlushClient{}, 100)
	c.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	sent, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sent != len(lines) {
		t.Errorf("sent = %d, want the %d kept records", sent, len(lines))
	}
	want := fmt.Sprintf(`"evicted_records":%d`, loss.EvictedRecords)
	if !bytes.Contains(logs.Bytes(), []byte("evicted unsent records")) || !bytes.Contains(logs.Bytes(), []byte(want)) {
		t.Fatalf("missing eviction warning with %s: %s", want, logs.String())
	}

	logs.Reset()
	if _, err := c.Run(context.Background()); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if bytes.Contains(logs.Bytes(), []byte("evicted")) {
		t.Fatalf("eviction reported twice: %s", logs.String())
	}
}

// TestSpoolEvictionCountsOnlyUnsentLines verifies lines the collector already
// acknowledged in an evicted segment are not reported as lost.
func TestSpoolEvictionCountsOnlyUnsentLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s := NewAuditSpool(path, 1000)
	for i := 0; i < 4; i++ {
		if err := s.Append(EventClassDecision, decisionRecord(t, fmt.Sprintf("a%d", i), 50)); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	// Ship one line of segment 1, then fail.
	c := NewCollector(path, &failAfterFlushClient{okBatches: 1}, 1)
	if _, err := c.Run(context.Background()); err == nil {
		t.Fatal("expected the collector to stop part way")
	}
	for i := 0; i < 20; i++ {
		if err := s.Append(EventClassDecision, decisionRecord(t, fmt.Sprintf("b%02d", i), 50)); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	loss := s.readMeta().Loss
	lines := spoolLines(t, s)
	// 24 appended, 1 acknowledged before its segment was evicted.
	if int64(len(lines))+loss.EvictedRecords+1 != 24 {
		t.Fatalf("kept %d + evicted %d + acked 1 != 24 (loss %+v)", len(lines), loss.EvictedRecords, loss)
	}
}

func TestSpoolRefusesLifecycleNearCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s := NewAuditSpool(path, 1000) // lifecycle ceiling is 900 bytes

	for i := 0; i < 17; i++ {
		if err := s.Append(EventClassDecision, decisionRecord(t, fmt.Sprintf("s%02d", i), 50)); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	// 850 + 50 reaches the ceiling exactly and is allowed.
	if err := s.Append(EventClassLifecycle, lifecycleRecord(t, 50)); err != nil {
		t.Fatalf("lifecycle append under the ceiling: %v", err)
	}
	// At 900 bytes the spool is at 90% of its cap: lifecycle is refused.
	if err := s.Append(EventClassLifecycle, lifecycleRecord(t, 50)); !errors.Is(err, errLifecycleBudget) {
		t.Fatalf("lifecycle append at 90%% = %v, want errLifecycleBudget", err)
	}
	if total := spoolTotal(t, s); total != 900 {
		t.Fatalf("spool = %d bytes, want 900 (refused record not written)", total)
	}
	// Decisions still fit in the reserved space, and fill the spool without
	// evicting anything.
	for i := 0; i < 2; i++ {
		if err := s.Append(EventClassDecision, decisionRecord(t, fmt.Sprintf("r%d", i), 50)); err != nil {
			t.Fatalf("decision append in reserved space: %v", err)
		}
	}
	loss := s.readMeta().Loss
	if loss.LifecycleRefused != 1 || loss.EvictedSegments != 0 {
		t.Fatalf("loss = %+v, want 1 lifecycle refusal and no evictions", loss)
	}

	var logs bytes.Buffer
	c := NewCollector(path, &fakeFlushClient{}, 100)
	c.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	if _, err := c.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !bytes.Contains(logs.Bytes(), []byte("refused lifecycle records")) {
		t.Fatalf("missing lifecycle refusal warning: %s", logs.String())
	}
}

func TestSpoolRefusesHarnessToolNearCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s := NewAuditSpool(path, 1000)

	for i := 0; i < 17; i++ {
		if err := s.Append(EventClassDecision, decisionRecord(t, fmt.Sprintf("s%02d", i), 50)); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	// 850 + 50 reaches the ceiling exactly and is allowed.
	if err := s.Append(EventClassHarnessTool, harnessToolRecord(t, 50)); err != nil {
		t.Fatalf("harness_tool append under the ceiling: %v", err)
	}
	// At 900 bytes the spool is at 90% of its cap: harness_tool is refused.
	if err := s.Append(EventClassHarnessTool, harnessToolRecord(t, 50)); !errors.Is(err, errLifecycleBudget) {
		t.Fatalf("harness_tool append at 90%% = %v, want errLifecycleBudget", err)
	}
	if total := spoolTotal(t, s); total != 900 {
		t.Fatalf("spool = %d bytes, want 900 (refused record not written)", total)
	}
	// Decisions still fit in the reserved space.
	for i := 0; i < 2; i++ {
		if err := s.Append(EventClassDecision, decisionRecord(t, fmt.Sprintf("r%d", i), 50)); err != nil {
			t.Fatalf("decision append in reserved space: %v", err)
		}
	}
	loss := s.readMeta().Loss
	if loss.HarnessToolRefused != 1 || loss.EvictedSegments != 0 {
		t.Fatalf("loss = %+v, want 1 harness_tool refusal and no evictions", loss)
	}

	var logs bytes.Buffer
	c := NewCollector(path, &fakeFlushClient{}, 100)
	c.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	if _, err := c.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !bytes.Contains(logs.Bytes(), []byte("refused harness_tool records")) {
		t.Fatalf("missing harness_tool refusal warning: %s", logs.String())
	}
}

func TestSpoolRefusesCredentialNearCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s := NewAuditSpool(path, 1000)

	for i := 0; i < 17; i++ {
		if err := s.Append(EventClassDecision, decisionRecord(t, fmt.Sprintf("s%02d", i), 50)); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	// 850 + 50 reaches the ceiling exactly and is allowed.
	if err := s.Append(EventClassCredential, credentialRecord(t, 50)); err != nil {
		t.Fatalf("credential append under the ceiling: %v", err)
	}
	// At 900 bytes the spool is at 90% of its cap: credential is refused.
	if err := s.Append(EventClassCredential, credentialRecord(t, 50)); !errors.Is(err, errLifecycleBudget) {
		t.Fatalf("credential append at 90%% = %v, want errLifecycleBudget", err)
	}
	if total := spoolTotal(t, s); total != 900 {
		t.Fatalf("spool = %d bytes, want 900 (refused record not written)", total)
	}
	// Decisions still fit in the reserved space.
	for i := 0; i < 2; i++ {
		if err := s.Append(EventClassDecision, decisionRecord(t, fmt.Sprintf("r%d", i), 50)); err != nil {
			t.Fatalf("decision append in reserved space: %v", err)
		}
	}
	loss := s.readMeta().Loss
	if loss.CredentialRefused != 1 || loss.EvictedSegments != 0 {
		t.Fatalf("loss = %+v, want 1 credential refusal and no evictions", loss)
	}

	var logs bytes.Buffer
	c := NewCollector(path, &fakeFlushClient{}, 100)
	c.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	if _, err := c.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !bytes.Contains(logs.Bytes(), []byte("refused credential records")) {
		t.Fatalf("missing credential refusal warning: %s", logs.String())
	}
}

func TestSpoolRejectsMislabelledAndOversizeRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s := NewAuditSpool(path, 1000)

	// A lifecycle record without its class would be read back as a decision.
	if err := s.Append(EventClassLifecycle, []byte(`{"event_type":"runtime.started"}`)); err == nil {
		t.Fatal("lifecycle record without event_class was accepted")
	}
	if err := s.Append("telemetry", []byte(`{}`)); err == nil {
		t.Fatal("unknown event class was accepted")
	}
	if err := s.Append(EventClassDecision, []byte("{\"span_id\":\"a\"}\n{}")); err == nil {
		t.Fatal("record with an embedded newline was accepted")
	}
	if err := s.Append(EventClassDecision, decisionRecord(t, "big", 1001)); !errors.Is(err, errRecordTooLarge) {
		t.Fatalf("oversize append = %v, want errRecordTooLarge", err)
	}
	if got := s.readMeta().Loss.OversizeRefused; got != 1 {
		t.Fatalf("oversize_refused = %d, want 1", got)
	}
}

// TestSpoolConcurrentWritersStayUnderCap appends from many goroutines, each
// with its own lock descriptor as separate processes would have, and checks
// the cap holds after every append and no record is lost uncounted.
func TestSpoolConcurrentWritersStayUnderCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	const (
		maxBytes = 2000
		writers  = 8
		each     = 40
	)

	var wg sync.WaitGroup
	errs := make(chan error, writers*each)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			s := NewAuditSpool(path, maxBytes)
			for i := 0; i < each; i++ {
				if err := AppendDecisionEvent(path, maxBytes, ev(fmt.Sprintf("w%d-%d", w, i))); err != nil {
					errs <- err
					return
				}
				_ = s.withLock(func() error {
					if total := spoolTotalLocked(s); total > maxBytes {
						errs <- fmt.Errorf("spool is %d bytes, cap %d", total, maxBytes)
					}
					return nil
				})
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	assertSpoolAccountsFor(t, NewAuditSpool(path, maxBytes), writers*each)
}

// TestSpoolConcurrentProcessesStayUnderCap runs writers as separate
// processes, the way one-shot authorize invocations share the spool.
func TestSpoolConcurrentProcessesStayUnderCap(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns subprocesses")
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	const (
		maxBytes = 3000
		procs    = 4
		each     = 40
	)
	var cmds []*exec.Cmd
	for p := 0; p < procs; p++ {
		cmd := exec.Command(os.Args[0], "-test.run=^TestSpoolHelperProcess$")
		cmd.Env = append(os.Environ(),
			"KEI_SPOOL_HELPER_PATH="+path,
			"KEI_SPOOL_HELPER_MAX="+strconv.Itoa(maxBytes),
			"KEI_SPOOL_HELPER_COUNT="+strconv.Itoa(each),
			"KEI_SPOOL_HELPER_ID="+strconv.Itoa(p),
		)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Start(); err != nil {
			t.Fatalf("start helper: %v", err)
		}
		cmds = append(cmds, cmd)
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("helper output: %s", out.String())
			}
		})
	}
	for _, cmd := range cmds {
		if err := cmd.Wait(); err != nil {
			t.Fatalf("helper failed: %v", err)
		}
	}
	assertSpoolAccountsFor(t, NewAuditSpool(path, maxBytes), procs*each)
}

// TestSpoolHelperProcess is the subprocess body for the test above.
func TestSpoolHelperProcess(t *testing.T) {
	path := os.Getenv("KEI_SPOOL_HELPER_PATH")
	if path == "" {
		t.Skip("helper process only")
	}
	maxBytes, _ := strconv.ParseInt(os.Getenv("KEI_SPOOL_HELPER_MAX"), 10, 64)
	count, _ := strconv.Atoi(os.Getenv("KEI_SPOOL_HELPER_COUNT"))
	id := os.Getenv("KEI_SPOOL_HELPER_ID")
	s := NewAuditSpool(path, maxBytes)
	for i := 0; i < count; i++ {
		if err := AppendDecisionEvent(path, maxBytes, ev(fmt.Sprintf("p%s-%d", id, i))); err != nil {
			t.Fatalf("append: %v", err)
		}
		_ = s.withLock(func() error {
			if total := spoolTotalLocked(s); total > maxBytes {
				t.Errorf("spool is %d bytes, cap %d", total, maxBytes)
			}
			return nil
		})
	}
}

func spoolTotalLocked(s *AuditSpool) int64 {
	segs, _ := s.segments()
	total, _ := fileSize(s.path)
	for _, seg := range segs {
		total += seg.size
	}
	return total
}

// assertSpoolAccountsFor checks every surviving line is a whole record and
// that kept plus counted-as-evicted equals everything appended.
func assertSpoolAccountsFor(t *testing.T, s *AuditSpool, appended int) {
	t.Helper()
	if total := spoolTotal(t, s); total > s.maxBytes {
		t.Fatalf("final spool is %d bytes, cap %d", total, s.maxBytes)
	}
	lines := spoolLines(t, s)
	for _, l := range lines {
		var e DecisionEvent
		if err := json.Unmarshal([]byte(l), &e); err != nil || e.SpanID == "" {
			t.Fatalf("torn or invalid line %q: %v", l, err)
		}
	}
	loss := s.readMeta().Loss
	if int64(len(lines))+loss.EvictedRecords != int64(appended) {
		t.Fatalf("kept %d + evicted %d != appended %d", len(lines), loss.EvictedRecords, appended)
	}
	if loss.EvictedRecords == 0 {
		t.Fatalf("expected the test load to force evictions")
	}
}

// TestCollectorResumesMidSegmentAfterCrash stops the collector after one
// batch of a segment and checks the next run sends only the rest.
func TestCollectorResumesMidSegmentAfterCrash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeJSONL(t, path, []DecisionEvent{ev("s1"), ev("s2"), ev("s3"), ev("s4"), ev("s5")})

	fake := &failAfterFlushClient{okBatches: 1}
	c := NewCollector(path, fake, 2)
	if _, err := c.Run(context.Background()); err == nil {
		t.Fatal("expected the second batch to fail")
	}
	st, err := readCollectorState(path + ".state")
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if st.Segment != 1 || st.LinesSent != 2 {
		t.Fatalf("state = %+v, want segment 1 with 2 lines sent", st)
	}

	// A fresh collector, as after a restart, resumes from the recorded line.
	fake.okBatches = -1
	c = NewCollector(path, fake, 2)
	if _, err := c.Run(context.Background()); err != nil {
		t.Fatalf("resumed Run: %v", err)
	}
	if got := strings.Join(fake.spans(), ","); got != "s1,s2,s3,s4,s5" {
		t.Fatalf("sent = %s, want each record once", got)
	}
	if segs, _ := c.spool.segments(); len(segs) != 0 {
		t.Fatalf("shipped segment not deleted: %+v", segs)
	}
}

// TestCollectorMigratesLegacyOffset covers upgrading a runtime whose collector
// kept a plain line count for the single, never-rotated spool file.
func TestCollectorMigratesLegacyOffset(t *testing.T) {
	legacy := []DecisionEvent{ev("s1"), ev("s2"), ev("s3")}

	t.Run("legacy file still active", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		writeJSONL(t, path, legacy)
		if err := os.WriteFile(path+".offset", []byte("2"), 0o644); err != nil {
			t.Fatalf("write offset: %v", err)
		}
		fake := &failAfterFlushClient{okBatches: -1}
		if _, err := NewCollector(path, fake, 100).Run(context.Background()); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if got := strings.Join(fake.spans(), ","); got != "s3" {
			t.Fatalf("sent = %s, want only the unsent legacy line s3", got)
		}
		if _, err := os.Stat(path + ".offset"); !os.IsNotExist(err) {
			t.Fatalf("legacy offset file was not removed")
		}
	})

	t.Run("writer rotated the legacy file first", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		writeJSONL(t, path, legacy)
		if err := os.WriteFile(path+".offset", []byte("2"), 0o644); err != nil {
			t.Fatalf("write offset: %v", err)
		}
		// The legacy file is larger than a segment, so the first capped
		// append seals it as segment 1.
		if err := AppendDecisionEvent(path, 1000, ev("s4")); err != nil {
			t.Fatalf("append: %v", err)
		}
		fake := &failAfterFlushClient{okBatches: -1}
		if _, err := NewCollector(path, fake, 100).Run(context.Background()); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if got := strings.Join(fake.spans(), ","); got != "s3,s4" {
			t.Fatalf("sent = %s, want s3,s4", got)
		}
	})

	t.Run("legacy segment already evicted", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		writeJSONL(t, path, legacy)
		if err := os.WriteFile(path+".offset", []byte("2"), 0o644); err != nil {
			t.Fatalf("write offset: %v", err)
		}
		s := NewAuditSpool(path, 1000)
		for i := 0; i < 20; i++ {
			if err := s.Append(EventClassDecision, decisionRecord(t, fmt.Sprintf("n%02d", i), 50)); err != nil {
				t.Fatalf("append: %v", err)
			}
		}
		if _, err := os.Stat(s.segmentPath(1)); !os.IsNotExist(err) {
			t.Fatalf("expected segment 1 to be evicted")
		}
		kept := len(spoolLines(t, s))
		fake := &failAfterFlushClient{okBatches: -1}
		if _, err := NewCollector(path, fake, 100).Run(context.Background()); err != nil {
			t.Fatalf("Run: %v", err)
		}
		// The stale count must not skip lines of a newer segment.
		if len(fake.spans()) != kept {
			t.Fatalf("sent %d, want all %d kept records", len(fake.spans()), kept)
		}
	})
}

// TestCollectorRecoversWhenStateSegmentEvicted verifies a position that
// points at a segment evicted since the last run is abandoned, and the next
// segment is shipped from its first line.
func TestCollectorRecoversWhenStateSegmentEvicted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s := NewAuditSpool(path, 1000)
	for i := 0; i < 2; i++ {
		if err := s.Append(EventClassDecision, decisionRecord(t, fmt.Sprintf("a%d", i), 50)); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	fake := &failAfterFlushClient{okBatches: 1}
	c := NewCollector(path, fake, 1)
	if _, err := c.Run(context.Background()); err == nil {
		t.Fatal("expected the collector to stop part way")
	}
	if st, _ := readCollectorState(path + ".state"); st.Segment != 1 || st.LinesSent != 1 {
		t.Fatalf("state = %+v, want segment 1 line 1", st)
	}

	for i := 0; i < 20; i++ {
		if err := s.Append(EventClassDecision, decisionRecord(t, fmt.Sprintf("b%02d", i), 50)); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if _, err := os.Stat(s.segmentPath(1)); !os.IsNotExist(err) {
		t.Fatalf("expected segment 1 to be evicted")
	}
	kept := spoolLines(t, s)

	fake.okBatches, fake.batches = -1, nil
	if _, err := c.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := fake.spans()
	if len(got) != len(kept) || !strings.Contains(kept[0], `"`+got[0]+`"`) {
		t.Fatalf("sent %v, want every kept record from %s", got, kept[0])
	}
}

// TestCollectorDoesNotRereadSpool verifies a poll seals the active file with
// a rename instead of reading it, reads each sealed segment once, and a poll
// with nothing new reads nothing.
func TestCollectorDoesNotRereadSpool(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	for _, e := range []DecisionEvent{ev("s1"), ev("s2")} {
		if err := AppendDecisionEvent(path, 0, e); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	var opened []string
	c := NewCollector(path, &fakeFlushClient{}, 100)
	c.open = func(name string) (*os.File, error) {
		opened = append(opened, name)
		return os.Open(name)
	}

	for poll := 0; poll < 3; poll++ {
		if _, err := c.Run(context.Background()); err != nil {
			t.Fatalf("Run %d: %v", poll, err)
		}
	}
	if len(opened) != 1 || opened[0] == path || !strings.HasPrefix(opened[0], path+".") {
		t.Fatalf("opened = %v, want the one sealed segment and never the active file", opened)
	}

	if err := AppendDecisionEvent(path, 0, ev("s3")); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := c.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(opened) != 2 || opened[1] == opened[0] {
		t.Fatalf("opened = %v, want only the new segment on the next poll", opened)
	}
}

// TestEmitDecisionLogsSpoolFailure verifies that EmitDecision writes the
// append error to stderr instead of silently dropping it.
func TestEmitDecisionLogsSpoolFailure(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	path := filepath.Join(blocker, "audit.jsonl")
	if err := AppendDecisionEvent(path, 0, ev("s1")); err == nil {
		t.Fatal("expected the append to fail under a file")
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	origStderr := os.Stderr
	os.Stderr = w

	EmitDecision(path, 0, ev("s1"))
	w.Close()
	os.Stderr = origStderr

	captured, _ := io.ReadAll(r)
	r.Close()
	if len(captured) == 0 {
		t.Fatal("expected an error on stderr")
	}
	if !strings.Contains(string(captured), "audit: failed to append decision event") {
		t.Fatalf("stderr = %q, want audit failure message", string(captured))
	}
}
