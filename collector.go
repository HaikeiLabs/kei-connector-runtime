package connectorruntime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"mime"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ABACFlushClient ships a batch of decision events to ABAC's audit flush
// endpoint. It is an interface so the collector is testable without a network.
type ABACFlushClient interface {
	Flush(ctx context.Context, records []DecisionEvent) (int, error)
}

type abacFlushClient struct {
	baseURL string
	path    string
	headers map[string]string
	client  *http.Client
}

// NewABACFlushClient builds a client that POSTs to <baseURL>/api/v1/audit/flush.
// It carries no credential and is intended for deployments in which ABAC has
// no auth configured (local development). Production deployments (and customer
// runtimes) must use NewABACFlushClientFromConfig instead.
func NewABACFlushClient(baseURL string, timeout time.Duration) ABACFlushClient {
	return &abacFlushClient{
		baseURL: baseURL,
		path:    "/api/v1/audit/flush",
		client:  &http.Client{Timeout: timeout},
	}
}

// NewABACFlushClientFromConfig builds a client whose flush destination and
// credential match the runtime mode of cfg:
//   - runtime mode POSTs <KEI_RUNTIME_CONTROL_PLANE_URL>/api/v1/runtime/audit/flush
//     with the installation token as an Authorization bearer. Customer runtimes
//     never receive the internal API secret.
//   - legacy mode POSTs <ABAC_URL>/api/v1/audit/flush with X-KEI-API-Key when an
//     ABAC_API_SECRET is configured, matching the authorize client.
func NewABACFlushClientFromConfig(cfg Config, timeout time.Duration) ABACFlushClient {
	if cfg.IsRuntime() {
		base := cfg.RuntimeControlPlaneURL
		if base == "" {
			base = cfg.ABACURL
		}
		return &abacFlushClient{
			baseURL: base,
			path:    "/api/v1/runtime/audit/flush",
			headers: map[string]string{"Authorization": "Bearer " + cfg.RuntimeToken},
			client:  &http.Client{Timeout: timeout},
		}
	}
	client := &abacFlushClient{
		baseURL: cfg.ABACURL,
		path:    "/api/v1/audit/flush",
		client:  &http.Client{Timeout: timeout},
	}
	if cfg.ABACSecret != "" {
		client.headers = map[string]string{"X-KEI-API-Key": cfg.ABACSecret}
	}
	return client
}

func (c *abacFlushClient) Flush(ctx context.Context, records []DecisionEvent) (int, error) {
	body, err := json.Marshal(map[string][]DecisionEvent{"records": records})
	if err != nil {
		return 0, fmt.Errorf("marshal flush: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+c.path, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("build flush request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("flush request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("flush returned status %d", resp.StatusCode)
	}
	var out struct {
		Upserted int `json:"upserted"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, fmt.Errorf("decode flush response: %w", err)
	}
	return out.Upserted, nil
}

// LifecycleFlushClient ships runtime lifecycle records (state changes such as
// started, degraded, recovered) to their own flush route. The policy catalog
// has no such route yet, so the collector runs without one and counts and
// logs lifecycle records as skipped; they must never reach the decision
// endpoint, where they would be stored as blank decisions.
type LifecycleFlushClient interface {
	FlushLifecycle(ctx context.Context, records []json.RawMessage) (int, error)
}

type lifecycleFlushClient struct {
	baseURL     string
	path        string
	headers     map[string]string
	client      *http.Client
	requestMu   sync.Mutex
	nextRequest time.Time
}

type lifecycleFlushHTTPError struct {
	statusCode     int
	retryAfter     time.Duration
	contentType    string
	server         string
	upstreamStatus string
	responseFlags  string
	upstreamTime   string
}

func (e *lifecycleFlushHTTPError) Error() string {
	return fmt.Sprintf("lifecycle flush returned status %d", e.statusCode)
}

func lifecycleRetryDelay(err error) (time.Duration, bool) {
	var flushErr *lifecycleFlushHTTPError
	if !errors.As(err, &flushErr) || flushErr.statusCode != http.StatusTooManyRequests {
		return 0, false
	}
	// Retry-After is advisory and bounded so a malformed/misconfigured upstream
	// cannot suspend delivery indefinitely. Missing/invalid hints retry promptly.
	delay := flushErr.retryAfter
	if delay <= 0 {
		delay = time.Second
	}
	if delay > 5*time.Minute {
		delay = 5 * time.Minute
	}
	return delay, true
}

// lifecycleFlushLogAttrs returns only explicitly allowlisted, bounded response
// metadata. Never inspect or log the response body or arbitrary headers.
func lifecycleFlushLogAttrs(err error) []any {
	var flushErr *lifecycleFlushHTTPError
	if !errors.As(err, &flushErr) {
		return nil
	}
	attrs := []any{"lifecycle_flush_status", flushErr.statusCode}
	if flushErr.contentType != "" {
		attrs = append(attrs, "lifecycle_flush_content_type", flushErr.contentType)
	}
	if flushErr.server != "" {
		attrs = append(attrs, "lifecycle_flush_server", flushErr.server)
	}
	if flushErr.upstreamStatus != "" {
		attrs = append(attrs, "lifecycle_flush_upstream_status", flushErr.upstreamStatus)
	}
	if flushErr.responseFlags != "" {
		attrs = append(attrs, "lifecycle_flush_proxy_response_flags", flushErr.responseFlags)
	}
	if flushErr.upstreamTime != "" {
		attrs = append(attrs, "lifecycle_flush_upstream_service_time_ms", flushErr.upstreamTime)
	}
	return attrs
}

func lifecycleFlushResponseError(resp *http.Response) error {
	e := &lifecycleFlushHTTPError{statusCode: resp.StatusCode}
	if resp.StatusCode == http.StatusTooManyRequests {
		e.retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())
	}
	if values := resp.Header.Values("Content-Type"); len(values) == 1 && len(values[0]) <= 256 {
		if mediaType, _, err := mime.ParseMediaType(values[0]); err == nil {
			e.contentType = mediaType
		}
	}
	if values := resp.Header.Values("Server"); len(values) == 1 && safeServerHeader(values[0]) {
		e.server = values[0]
	}
	if values := resp.Header.Values("X-Proxy-Upstream-Status"); len(values) == 1 && validHTTPStatusHeader(values[0]) {
		e.upstreamStatus = values[0]
	}
	if values := resp.Header.Values("X-Envoy-Response-Flags"); len(values) == 1 && safeEnvoyFlags(values[0]) {
		e.responseFlags = values[0]
	}
	if values := resp.Header.Values("X-Envoy-Upstream-Service-Time"); len(values) == 1 && boundedDigits(values[0], 8) {
		e.upstreamTime = values[0]
	}
	return e
}

func safeServerHeader(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	product, version, hasVersion := strings.Cut(value, "/")
	switch strings.ToLower(product) {
	case "envoy", "nginx", "awselb", "cloudflare", "caddy", "apache", "openresty", "traefik":
	default:
		return false
	}
	if !hasVersion {
		return true
	}
	if version == "" || len(version) > 24 {
		return false
	}
	for _, r := range version {
		if !(r >= '0' && r <= '9' || r == '.') {
			return false
		}
	}
	return true
}

func validHTTPStatusHeader(value string) bool {
	if len(value) != 3 || !boundedDigits(value, 3) {
		return false
	}
	status, _ := strconv.Atoi(value)
	return status >= 100 && status <= 599
}

func safeEnvoyFlags(value string) bool {
	if len(value) == 0 || len(value) > 32 {
		return false
	}
	for _, r := range value {
		if !(r >= 'A' && r <= 'Z' || r == ',') {
			return false
		}
	}
	return true
}

func boundedDigits(value string, maxLen int) bool {
	if len(value) == 0 || len(value) > maxLen {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// NewLifecycleFlushClientFromConfig builds a client that POSTs lifecycle
// records to <KEI_RUNTIME_CONTROL_PLANE_URL>/api/v1/runtime/audit/lifecycle:flush
// with the installation token as an Authorization bearer. It returns nil when no
// runtime token is configured (legacy harness mode), so the collector skips
// lifecycle records without erroring.
func NewLifecycleFlushClientFromConfig(cfg Config, timeout time.Duration) LifecycleFlushClient {
	if cfg.RuntimeToken == "" {
		return nil
	}
	base := cfg.RuntimeControlPlaneURL
	if base == "" {
		base = cfg.ABACURL
	}
	return &lifecycleFlushClient{
		baseURL: base,
		path:    "/api/v1/runtime/audit/lifecycle:flush",
		headers: map[string]string{"Authorization": "Bearer " + cfg.RuntimeToken},
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *lifecycleFlushClient) FlushLifecycle(ctx context.Context, records []json.RawMessage) (int, error) {
	body, err := json.Marshal(map[string][]json.RawMessage{"records": records})
	if err != nil {
		return 0, fmt.Errorf("marshal lifecycle flush: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+c.path, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("build lifecycle flush request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	c.requestMu.Lock()
	defer c.requestMu.Unlock()
	if wait := time.Until(c.nextRequest); wait > 0 {
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0, ctx.Err()
		case <-timer.C:
		}
	}
	resp, err := c.client.Do(req)
	c.nextRequest = time.Now().Add(100 * time.Millisecond)
	if err != nil {
		return 0, fmt.Errorf("lifecycle flush request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return 0, lifecycleFlushResponseError(resp)
	}
	var out struct {
		Upserted int `json:"upserted"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, fmt.Errorf("decode lifecycle flush response: %w", err)
	}
	return out.Upserted, nil
}

// Collector ships pending JSONL decision events to ABAC. Each run seals the
// active spool file into a segment under the spool lock, then streams sealed
// segments oldest first, so it never rereads data it has already shipped. Its
// position, {segment, lines_sent}, lives in <jsonlPath>.state, so it is
// resumable across runs, and a segment is deleted only after every line in it
// has been acknowledged. Because the flush is idempotent (ABAC dedupes on
// span_id), re-sending an already flushed batch after a crash is safe.
type Collector struct {
	jsonlPath string
	statePath string
	// legacyOffsetPath is the pre-segment state file: a plain count of lines
	// already sent from the single, never-rotated spool file.
	legacyOffsetPath string
	spool            *auditSpool
	abac             ABACFlushClient
	lifecycle        LifecycleFlushClient
	batchSize        int
	logger           *slog.Logger
	// open is os.Open; tests replace it to observe which files a run reads.
	open func(name string) (*os.File, error)
}

// collectorState is the collector's position in the spool plus the loss
// counters it has already reported.
type collectorState struct {
	// Segment is the segment being shipped, or 0 when none is in progress.
	Segment      uint64    `json:"segment"`
	LinesSent    int       `json:"lines_sent"`
	ReportedLoss spoolLoss `json:"reported_loss"`
}

// NewCollector builds a collector for the given JSONL path. The state file
// defaults to <jsonlPath>.state.
func NewCollector(jsonlPath string, abac ABACFlushClient, batchSize int) *Collector {
	if batchSize <= 0 {
		batchSize = 100
	}
	return &Collector{
		jsonlPath:        jsonlPath,
		statePath:        jsonlPath + ".state",
		legacyOffsetPath: jsonlPath + ".offset",
		// The collector never appends, so the cap does not apply to it.
		spool:     newAuditSpool(jsonlPath, 0),
		abac:      abac,
		batchSize: batchSize,
		logger:    slog.Default(),
		open:      os.Open,
	}
}

// Run flushes all pending records and returns how many were sent.
func (c *Collector) Run(ctx context.Context) (int, error) {
	st, err := readCollectorState(c.statePath)
	if err != nil {
		// Resending is safe and a stuck collector is not: start over from the
		// oldest segment rather than failing every poll.
		c.logger.Warn("audit collector state unreadable; resending from the oldest segment", "path", c.statePath, "error", err)
		st = collectorState{}
	}
	if _, err := os.Stat(filepath.Dir(c.jsonlPath)); os.IsNotExist(err) {
		return 0, nil
	}

	var (
		segs []spoolSegment
		loss spoolLoss
	)
	err = c.spool.withLock(func() error {
		if err := c.migrateLegacyOffset(&st); err != nil {
			return err
		}
		meta := c.spool.readMeta()
		if _, err := c.spool.sealActiveLocked(&meta, st.Segment+1); err != nil {
			return err
		}
		loss = meta.Loss
		segs, err = c.spool.segments()
		return err
	})
	if err != nil {
		return 0, err
	}
	if err := c.reportLoss(&st, loss); err != nil {
		return 0, err
	}

	sent := 0
	var skipped skippedRecords
	defer func() { skipped.log(c.logger, c.jsonlPath) }()
	for _, seg := range segs {
		n, err := c.shipSegment(ctx, seg, &st, &skipped)
		sent += n
		if err != nil {
			return sent, err
		}
	}
	return sent, nil
}

// migrateLegacyOffset converts a pre-segment .offset file into segment state.
// That count describes the single spool file as it existed before this
// version, which becomes segment 1 when it is first rotated: by a writer
// that crossed the segment size, or here. If segment 1 was since evicted,
// those lines are gone and the count no longer applies. Called under the
// spool lock.
func (c *Collector) migrateLegacyOffset(st *collectorState) error {
	data, err := os.ReadFile(c.legacyOffsetPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read legacy offset: %w", err)
	}
	if _, err := os.Stat(c.statePath); err == nil {
		// Already migrated; the remove below was interrupted.
		return removeFile(c.legacyOffsetPath)
	}
	sentCount, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return fmt.Errorf("parse legacy offset: %w", err)
	}
	*st = collectorState{}
	segs, err := c.spool.segments()
	if err != nil {
		return err
	}
	meta := c.spool.readMeta()
	switch {
	case len(segs) > 0 && segs[0].seq == 1:
		*st = collectorState{Segment: 1, LinesSent: sentCount}
	case len(segs) == 0 && meta.NextSeq <= 1:
		// Nothing has rotated yet, so the legacy file is still the active
		// file. Seal it now so the count is tied to that exact data.
		seq, err := c.spool.sealActiveLocked(&meta, 1)
		if err != nil {
			return err
		}
		if seq != 0 {
			*st = collectorState{Segment: seq, LinesSent: sentCount}
		}
	}
	if err := c.writeState(*st); err != nil {
		return err
	}
	return removeFile(c.legacyOffsetPath)
}

// reportLoss logs any spool loss since the last report. Eviction must never
// be silent: the counters live in the spool sidecar and each increase is
// logged once here.
func (c *Collector) reportLoss(st *collectorState, loss spoolLoss) error {
	if loss == st.ReportedLoss {
		return nil
	}
	prev := st.ReportedLoss
	if loss.EvictedSegments > prev.EvictedSegments || loss.EvictedRecords > prev.EvictedRecords {
		c.logger.Warn("audit spool evicted unsent records to stay within its cap",
			"path", c.jsonlPath,
			"evicted_segments", loss.EvictedSegments-prev.EvictedSegments,
			"evicted_records", loss.EvictedRecords-prev.EvictedRecords,
			"evicted_bytes", loss.EvictedBytes-prev.EvictedBytes,
			"evicted_records_total", loss.EvictedRecords)
	}
	if loss.LifecycleRefused > prev.LifecycleRefused {
		c.logger.Warn("audit spool refused lifecycle records to keep space for decisions",
			"path", c.jsonlPath,
			"refused_records", loss.LifecycleRefused-prev.LifecycleRefused,
			"refused_records_total", loss.LifecycleRefused)
	}
	if loss.OversizeRefused > prev.OversizeRefused {
		c.logger.Warn("audit spool refused records larger than its cap",
			"path", c.jsonlPath,
			"refused_records", loss.OversizeRefused-prev.OversizeRefused,
			"refused_records_total", loss.OversizeRefused)
	}
	// A reset sidecar lowers the counters; adopt them without logging.
	st.ReportedLoss = loss
	return c.writeState(*st)
}

// shipSegment streams one sealed segment in batches, resuming after the lines
// already acknowledged when st points at it, and deletes it once every line
// has been handled. A segment evicted before or during the read is skipped or
// finished from the open descriptor; either way its loss was counted by the
// writer that evicted it.
func (c *Collector) shipSegment(ctx context.Context, seg spoolSegment, st *collectorState, skipped *skippedRecords) (int, error) {
	skip := 0
	if st.Segment == seg.seq {
		skip = st.LinesSent
	}
	f, err := c.open(seg.path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("open audit segment: %w", err)
	}
	defer func() { _ = f.Close() }()

	r := bufio.NewReader(f)
	sent, lineNo := 0, 0
	var batch []string
	flush := func() error {
		n, err := c.flushBatch(ctx, parseBatch(batch), skipped)
		sent += n
		if err != nil {
			return err
		}
		// Advance past every line in this batch (valid or malformed) so we
		// never re-send or re-parse them.
		st.Segment, st.LinesSent = seg.seq, lineNo
		batch = batch[:0]
		return c.writeState(*st)
	}
	for {
		line, err := nextSpoolLine(r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return sent, fmt.Errorf("read audit segment: %w", err)
		}
		lineNo++
		if lineNo <= skip {
			continue
		}
		batch = append(batch, string(line))
		if len(batch) == c.batchSize {
			if err := flush(); err != nil {
				return sent, err
			}
		}
	}
	if len(batch) > 0 {
		if err := flush(); err != nil {
			return sent, err
		}
	}

	// Clear the position before deleting: a crash in between re-sends this
	// segment, which is safe, rather than applying its position to another.
	st.Segment, st.LinesSent = 0, 0
	if err := c.writeState(*st); err != nil {
		return sent, err
	}
	if err := removeFile(seg.path); err != nil {
		return sent, fmt.Errorf("delete shipped audit segment: %w", err)
	}
	return sent, nil
}

// skippedRecords counts spool lines a run consumed without sending them to
// the decision endpoint. They are logged as counts only, never contents.
type skippedRecords struct {
	lifecycle int
	unknown   int
	malformed int
}

func (s *skippedRecords) add(b parsedBatch, lifecycleShipped bool) {
	if !lifecycleShipped {
		s.lifecycle += len(b.lifecycle)
	}
	s.unknown += b.unknown
	s.malformed += b.malformed
}

// log reports what a run skipped so a record never disappears silently.
func (s skippedRecords) log(logger *slog.Logger, path string) {
	if s.lifecycle > 0 {
		logger.Warn("audit collector skipped lifecycle records; no lifecycle flush route is configured", "path", path, "records", s.lifecycle)
	}
	if s.unknown > 0 {
		logger.Warn("audit collector skipped records with an unknown event_class", "path", path, "records", s.unknown)
	}
	if s.malformed > 0 {
		logger.Warn("audit collector skipped malformed records", "path", path, "records", s.malformed)
	}
}

// flushBatch sends a parsed batch's decisions to ABAC and its lifecycle
// records to the lifecycle route when one is configured. It returns the
// number of decisions sent. Flushes are idempotent, so a batch that fails
// part way is safe to resend whole.
func (c *Collector) flushBatch(ctx context.Context, b parsedBatch, skipped *skippedRecords) (int, error) {
	if len(b.decisions) > 0 {
		payload, _ := json.Marshal(map[string][]DecisionEvent{"records": b.decisions})
		if _, err := c.abac.Flush(ctx, b.decisions); err != nil {
			return 0, err
		}
		c.logger.Info("audit collector flush succeeded", "path", c.jsonlPath, "event_class", eventClassDecision, "records_sent", len(b.decisions), "payload_bytes", len(payload))
	}
	if len(b.lifecycle) > 0 && c.lifecycle != nil {
		payload, _ := json.Marshal(map[string][]json.RawMessage{"records": b.lifecycle})
		if _, err := c.lifecycle.FlushLifecycle(ctx, b.lifecycle); err != nil {
			return len(b.decisions), err
		}
		c.logger.Info("audit collector flush succeeded", "path", c.jsonlPath, "event_class", eventClassLifecycle, "events_sent", len(b.lifecycle), "payload_bytes", len(payload))
	}
	skipped.add(b, c.lifecycle != nil)
	return len(b.decisions), nil
}

// RunPolling runs the collector repeatedly until ctx is cancelled. A failed
// run leaves the offset unchanged; the next tick retries the same records.
// Polling is optional so the existing one-shot CLI remains compatible.
func (c *Collector) RunPolling(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = time.Minute
	}

	const (
		initialRetry = time.Second
		maxRetry     = 15 * time.Minute
	)
	var (
		retryDelay  time.Duration
		readyLogged bool
	)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		sent, err := c.Run(ctx)
		if err == nil {
			if !readyLogged {
				pendingBytes, pendingFiles, oldestAge := c.pendingStats()
				c.logger.Info("audit collector ready", "path", c.jsonlPath, "records_flushed", sent, "pending_bytes", pendingBytes, "pending_files", pendingFiles, "oldest_pending_age_seconds", oldestAge)
				readyLogged = true
			}
			retryDelay = 0
		} else {
			if delay, throttled := lifecycleRetryDelay(err); throttled {
				pendingBytes, pendingFiles, oldestAge := c.pendingStats()
				attrs := []any{"path", c.jsonlPath, "retry_in", delay, "pending_bytes", pendingBytes, "pending_files", pendingFiles, "oldest_pending_age_seconds", oldestAge, "error", err}
				attrs = append(attrs, lifecycleFlushLogAttrs(err)...)
				c.logger.Error("audit collector throttled; retaining spool and retrying", attrs...)
				timer := time.NewTimer(delay)
				select {
				case <-ctx.Done():
					if !timer.Stop() {
						<-timer.C
					}
					return ctx.Err()
				case <-timer.C:
				}
				continue
			}
			if retryDelay == 0 {
				retryDelay = initialRetry
			} else if retryDelay < maxRetry {
				retryDelay *= 2
				if retryDelay > maxRetry {
					retryDelay = maxRetry
				}
			}
			jitter := time.Duration(rand.Float64() * float64(retryDelay) / 4)
			retryIn := retryDelay + jitter
			pendingBytes, pendingFiles, oldestAge := c.pendingStats()
			attrs := []any{"path", c.jsonlPath, "retry_in", retryIn, "pending_bytes", pendingBytes, "pending_files", pendingFiles, "oldest_pending_age_seconds", oldestAge, "error", err}
			attrs = append(attrs, lifecycleFlushLogAttrs(err)...)
			c.logger.Error("audit collector flush failed; retaining spool and retrying", attrs...)
			timer := time.NewTimer(retryIn)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return ctx.Err()
			case <-timer.C:
			}
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// pendingStats returns the backlog size and age of its oldest valid record.
// These values are emitted as structured fields so a runtime can scrape them
// as metrics without making the collector's authorization path depend on a
// metrics server.
//
// The backlog is measured in bytes and files from directory metadata rather
// than by counting records, so reporting it never reads the spool. The age
// comes from the first pending decision in the oldest file, which is the
// oldest record in append order; only the lines up to it are read.
func (c *Collector) pendingStats() (pendingBytes int64, pendingFiles int, oldestAgeSeconds int64) {
	st, _ := readCollectorState(c.statePath)
	segs, _ := c.spool.segments()
	for _, seg := range segs {
		pendingBytes += seg.size
		pendingFiles++
	}
	if size, _ := fileSize(c.jsonlPath); size > 0 {
		pendingBytes += size
		pendingFiles++
	}

	oldestPath, skip := c.jsonlPath, 0
	if len(segs) > 0 {
		oldestPath = segs[0].path
		if st.Segment == segs[0].seq {
			skip = st.LinesSent
		}
	}
	oldest := firstPendingDecisionTime(oldestPath, skip)
	if oldest.IsZero() {
		return pendingBytes, pendingFiles, 0
	}
	age := time.Since(oldest).Seconds()
	if age < 0 {
		age = 0
	}
	return pendingBytes, pendingFiles, int64(age)
}

// firstPendingDecisionTime returns invoked_at of the first decision after
// skip lines, reading no further than that record.
func firstPendingDecisionTime(path string, skip int) time.Time {
	f, err := os.Open(path)
	if err != nil {
		return time.Time{}
	}
	defer func() { _ = f.Close() }()
	r := bufio.NewReader(f)
	for lineNo := 1; ; lineNo++ {
		line, err := nextSpoolLine(r)
		if err != nil {
			return time.Time{}
		}
		if lineNo <= skip {
			continue
		}
		if b := parseBatch([]string{string(line)}); len(b.decisions) == 1 && !b.decisions[0].InvokedAt.IsZero() {
			return b.decisions[0].InvokedAt
		}
	}
}

// readCollectorState loads the collector position. A missing file is the
// zero state: start at the oldest segment.
func readCollectorState(path string) (collectorState, error) {
	var st collectorState
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return st, nil
		}
		return st, fmt.Errorf("read state: %w", err)
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return collectorState{}, fmt.Errorf("parse state: %w", err)
	}
	return st, nil
}

func (c *Collector) writeState(st collectorState) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(c.statePath, data); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	return nil
}

func removeFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Decision and lifecycle records share one spool file and are told apart by
// event_class. A line with no event_class is a decision: every line written
// before the discriminator existed has none, and DecisionEvent itself never
// carries one, so a decision still forwards to ABAC unchanged.
const (
	eventClassDecision  = "decision"
	eventClassLifecycle = "lifecycle"
)

// parsedBatch is one batch of spool lines split by event class. Only
// decisions are ever sent to the decision flush endpoint.
type parsedBatch struct {
	decisions []DecisionEvent
	lifecycle []json.RawMessage
	unknown   int
	malformed int
}

// parseBatch decodes raw lines and splits them by event_class: absent or
// "decision" is a DecisionEvent, "lifecycle" is a lifecycle record, and any
// other class is unknown. Non-object and undecodable lines are malformed.
// Anything that is not unambiguously a decision is never returned as one,
// because the decision decoder would zero-fill it into a blank audit record.
func parseBatch(lines []string) parsedBatch {
	var out parsedBatch
	for _, l := range lines {
		raw := []byte(l)
		if len(raw) == 0 || raw[0] != '{' {
			out.malformed++
			continue
		}
		var probe struct {
			EventClass *string `json:"event_class"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			out.malformed++
			continue
		}
		class := eventClassDecision
		if probe.EventClass != nil {
			class = *probe.EventClass
		}
		switch class {
		case eventClassDecision:
			e, ok := parseAuditLine(l)
			if !ok {
				out.malformed++
				continue
			}
			out.decisions = append(out.decisions, e)
		case eventClassLifecycle:
			out.lifecycle = append(out.lifecycle, json.RawMessage(raw))
		default:
			out.unknown++
		}
	}
	return out
}

func runCollector(args []string) int {
	fs := flag.NewFlagSet("collector", flag.ContinueOnError)
	jsonlPath := fs.String("jsonl", "", "audit JSONL file path (default $KEI_PROXY_AUDIT)")
	abacURL := fs.String("abac-url", "", "ABAC Engine URL (default $ABAC_URL)")
	batchSize := fs.Int("batch-size", 100, "records per flush batch")
	timeout := fs.Int("timeout", 30, "ABAC request timeout in seconds")
	poll := fs.Bool("poll", false, "poll for new records until terminated")
	pollInterval := fs.Duration("poll-interval", time.Minute, "poll interval when --poll is enabled")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	cfg := configFromEnv()
	if *jsonlPath == "" {
		*jsonlPath = cfg.AuditPath
	}
	if *abacURL != "" {
		cfg.ABACURL = *abacURL
		// In runtime mode the collector targets the runtime flush endpoint on
		// the control-plane gateway; honor an explicit override there too.
		if cfg.IsRuntime() {
			cfg.RuntimeControlPlaneURL = *abacURL
		}
	}
	if *jsonlPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --jsonl or KEI_PROXY_AUDIT is required")
		return 1
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid collector configuration: %v\n", err)
		return 1
	}

	client := NewABACFlushClientFromConfig(cfg, time.Duration(*timeout)*time.Second)
	lifecycleClient := NewLifecycleFlushClientFromConfig(cfg, time.Duration(*timeout)*time.Second)
	collector := NewCollector(*jsonlPath, client, *batchSize)
	collector.lifecycle = lifecycleClient
	if *poll {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := collector.RunPolling(ctx, *pollInterval); err != nil && !errors.Is(err, context.Canceled) {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}
		return 0
	}

	sent, err := collector.Run(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(os.Stdout, "flushed %d records\n", sent)
	return 0
}
