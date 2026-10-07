package runtime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/collector"
)

type ABACFlushClient interface {
	Flush(ctx context.Context, records []DecisionEvent) (int, error)
}

type abacFlushClient struct {
	baseURL string
	path    string
	headers map[string]string
	client  *http.Client
}

func NewABACFlushClient(baseURL string, timeout time.Duration) ABACFlushClient {
	return &abacFlushClient{
		baseURL: baseURL,
		path:    "/api/v1/audit/flush",
		client:  &http.Client{Timeout: timeout},
	}
}

func NewABACFlushClientFromConfig(cfg CollectorConfig, timeout time.Duration) ABACFlushClient {
	if cfg.IsRuntime() {
		base := cfg.ControlPlaneURL()
		if base == "" {
			base = cfg.FlushURL()
		}
		return &abacFlushClient{
			baseURL: base,
			path:    "/api/v1/runtime/audit/flush",
			headers: map[string]string{"Authorization": "Bearer " + cfg.Token()},
			client:  &http.Client{Timeout: timeout},
		}
	}
	client := &abacFlushClient{
		baseURL: cfg.FlushURL(),
		path:    "/api/v1/audit/flush",
		client:  &http.Client{Timeout: timeout},
	}
	if cfg.FlushSecret() != "" {
		client.headers = map[string]string{"X-KEI-API-Key": cfg.FlushSecret()}
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

type LifecycleFlushClient interface {
	FlushLifecycle(ctx context.Context, records []json.RawMessage) (int, error)
}

type HarnessToolFlushClient interface {
	FlushHarnessTool(ctx context.Context, records []json.RawMessage) (int, error)
}

type CredentialFlushClient interface {
	FlushCredential(ctx context.Context, records []json.RawMessage) (int, error)
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
	var lifecycleErr *lifecycleFlushHTTPError
	if errors.As(err, &lifecycleErr) {
		return throttleDelay(lifecycleErr.statusCode, lifecycleErr.retryAfter)
	}
	var harnessErr *harnessToolFlushHTTPError
	if errors.As(err, &harnessErr) {
		return throttleDelay(harnessErr.statusCode, harnessErr.retryAfter)
	}
	var auditErr *harnessAuditFlushHTTPError
	if errors.As(err, &auditErr) {
		return throttleDelay(auditErr.statusCode, auditErr.retryAfter)
	}
	return 0, false
}

func throttleDelay(statusCode int, retryAfter time.Duration) (time.Duration, bool) {
	if statusCode != http.StatusTooManyRequests {
		return 0, false
	}
	delay := retryAfter
	if delay <= 0 {
		delay = time.Second
	}
	if delay > 5*time.Minute {
		delay = 5 * time.Minute
	}
	return delay, true
}

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

func NewLifecycleFlushClientFromConfig(cfg CollectorConfig, timeout time.Duration) LifecycleFlushClient {
	if cfg.Token() == "" {
		return nil
	}
	base := cfg.ControlPlaneURL()
	if base == "" {
		base = cfg.FlushURL()
	}
	return &lifecycleFlushClient{
		baseURL: base,
		path:    "/api/v1/runtime/audit/lifecycle:flush",
		headers: map[string]string{"Authorization": "Bearer " + cfg.Token()},
		client:  &http.Client{Timeout: timeout},
	}
}

// harnessToolBatchMax is the catalog's hard cap on events per
// harness-tool-events:batchCreate request.
const harnessToolBatchMax = 500

// harnessToolIngestEvent is the only shape the skill-tool-mappings ingest
// endpoint accepts. It is built field-by-field from the spool record so that
// args_digest, args_ciphertext, tool_input, and any future field can never be
// forwarded.
type harnessToolIngestEvent struct {
	Tool        string `json:"tool"`
	Skill       string `json:"skill,omitempty"`
	HarnessKind string `json:"harness_kind"`
	ObservedAt  string `json:"observed_at"`
}

// rawHarnessToolRecord decodes only the four ingest fields from a spool
// harness_tool record. Every other field on the record is ignored on purpose.
type rawHarnessToolRecord struct {
	Tool        string `json:"tool"`
	Skill       string `json:"skill,omitempty"`
	HarnessKind string `json:"harness_kind"`
	ObservedAt  string `json:"observed_at"`
}

type harnessToolFlushClient struct {
	baseURL     string
	path        string
	headers     map[string]string
	client      *http.Client
	requestMu   sync.Mutex
	nextRequest time.Time
}

type harnessToolFlushHTTPError struct {
	statusCode int
	retryAfter time.Duration
}

func (e *harnessToolFlushHTTPError) Error() string {
	return fmt.Sprintf("harness_tool flush returned status %d", e.statusCode)
}

func harnessToolFlushResponseError(resp *http.Response) error {
	e := &harnessToolFlushHTTPError{statusCode: resp.StatusCode}
	if resp.StatusCode == http.StatusTooManyRequests {
		e.retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())
	}
	return e
}

func NewHarnessToolFlushClientFromConfig(cfg CollectorConfig, timeout time.Duration) HarnessToolFlushClient {
	if cfg.Token() == "" {
		return nil
	}
	base := cfg.ControlPlaneURL()
	if base == "" {
		base = cfg.FlushURL()
	}
	return &harnessToolFlushClient{
		baseURL: base,
		path:    "/api/v1/runtime/harness-tool-events:batchCreate",
		headers: map[string]string{"Authorization": "Bearer " + cfg.Token()},
		client:  &http.Client{Timeout: timeout},
	}
}

// canonicalHarnessKind maps the runtime's internal harness kind to the catalog
// domain. The spool records "claude"; the catalog expects "claude_code".
func canonicalHarnessKind(kind string) string {
	switch kind {
	case "claude":
		return "claude_code"
	default:
		return kind
	}
}

// FlushHarnessTool reduces each raw spool record to the four ingest fields,
// maps the harness kind, and POSTs them to the catalog in batches of at most
// harnessToolBatchMax. Delivery is at-least-once: a failed batch returns an
// error so the collector retains the spool and retries.
func (c *harnessToolFlushClient) FlushHarnessTool(ctx context.Context, records []json.RawMessage) (int, error) {
	events := make([]harnessToolIngestEvent, 0, len(records))
	for _, raw := range records {
		var rec rawHarnessToolRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			continue
		}
		events = append(events, harnessToolIngestEvent{
			Tool:        rec.Tool,
			Skill:       rec.Skill,
			HarnessKind: canonicalHarnessKind(rec.HarnessKind),
			ObservedAt:  rec.ObservedAt,
		})
	}
	total := 0
	for start := 0; start < len(events); start += harnessToolBatchMax {
		end := start + harnessToolBatchMax
		if end > len(events) {
			end = len(events)
		}
		n, err := c.flushHarnessToolChunk(ctx, events[start:end])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func (c *harnessToolFlushClient) flushHarnessToolChunk(ctx context.Context, events []harnessToolIngestEvent) (int, error) {
	body, err := json.Marshal(map[string][]harnessToolIngestEvent{"events": events})
	if err != nil {
		return 0, fmt.Errorf("marshal harness_tool flush: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+c.path, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("build harness_tool flush request: %w", err)
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
		return 0, fmt.Errorf("harness_tool flush request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return 0, harnessToolFlushResponseError(resp)
	}
	var out struct {
		Upserted int `json:"upserted"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, fmt.Errorf("decode harness_tool flush response: %w", err)
	}
	return out.Upserted, nil
}

func NewCredentialFlushClientFromConfig(CollectorConfig, time.Duration) CredentialFlushClient {
	return nil
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

type Collector struct {
	jsonlPath         string
	statePath         string
	legacyOffsetPath  string
	spool             *AuditSpool
	FlushClient       ABACFlushClient
	LifecycleClient   LifecycleFlushClient
	HarnessToolClient HarnessToolFlushClient
	// HarnessAuditClient ships harness_tool records to the audit log
	// (POST /api/v1/runtime/audit:flush) in addition to HarnessToolClient's
	// skill-tool-mappings ingest.
	HarnessAuditClient HarnessAuditFlushClient
	CredentialClient   CredentialFlushClient
	batchSize          int
	logger             *slog.Logger
	open               func(name string) (*os.File, error)
}

func NewCollector(jsonlPath string, abac ABACFlushClient, batchSize int) *Collector {
	if batchSize <= 0 {
		batchSize = 100
	}
	return &Collector{
		jsonlPath:        jsonlPath,
		statePath:        jsonlPath + ".state",
		legacyOffsetPath: jsonlPath + ".offset",
		spool:            NewAuditSpool(jsonlPath, 0),
		FlushClient:      abac,
		batchSize:        batchSize,
		logger:           slog.Default(),
		open:             os.Open,
	}
}

func (c *Collector) Run(ctx context.Context) (int, error) {
	st, err := readCollectorState(c.statePath)
	if err != nil {
		c.logger.Warn("audit collector state unreadable; resending from the oldest segment", "path", c.statePath, "error", err)
		st = &collectorState{}
	}
	if _, err := os.Stat(filepath.Dir(c.jsonlPath)); os.IsNotExist(err) {
		return 0, nil
	}

	var (
		segs []spoolSegment
		loss spoolLoss
	)
	err = c.spool.withLock(func() error {
		if err := c.migrateLegacyOffset(st); err != nil {
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
	if err := c.reportLoss(st, loss); err != nil {
		return 0, err
	}

	sent := 0
	var skipped skippedRecords
	defer func() { skipped.log(c.logger, c.jsonlPath) }()
	for _, seg := range segs {
		n, err := c.shipSegment(ctx, seg, st, &skipped)
		sent += n
		if err != nil {
			return sent, err
		}
	}
	return sent, nil
}

func (c *Collector) migrateLegacyOffset(st *collectorState) error {
	data, err := os.ReadFile(c.legacyOffsetPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read legacy offset: %w", err)
	}
	if _, err := os.Stat(c.statePath); err == nil {
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
	if loss.HarnessToolRefused > prev.HarnessToolRefused {
		c.logger.Warn("audit spool refused harness_tool records to keep space for decisions",
			"path", c.jsonlPath,
			"refused_records", loss.HarnessToolRefused-prev.HarnessToolRefused,
			"refused_records_total", loss.HarnessToolRefused)
	}
	if loss.CredentialRefused > prev.CredentialRefused {
		c.logger.Warn("audit spool refused credential records to keep space for decisions",
			"path", c.jsonlPath,
			"refused_records", loss.CredentialRefused-prev.CredentialRefused,
			"refused_records_total", loss.CredentialRefused)
	}
	if loss.OversizeRefused > prev.OversizeRefused {
		c.logger.Warn("audit spool refused records larger than its cap",
			"path", c.jsonlPath,
			"refused_records", loss.OversizeRefused-prev.OversizeRefused,
			"refused_records_total", loss.OversizeRefused)
	}
	st.ReportedLoss = loss
	return c.writeState(*st)
}

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

	st.Segment, st.LinesSent = 0, 0
	if err := c.writeState(*st); err != nil {
		return sent, err
	}
	if err := removeFile(seg.path); err != nil {
		return sent, fmt.Errorf("delete shipped audit segment: %w", err)
	}
	return sent, nil
}

type skippedRecords struct {
	lifecycle   int
	harnessTool int
	credential  int
	unknown     int
	malformed   int
}

func (s *skippedRecords) add(b parsedBatch, lifecycleShipped, harnessToolShipped, credentialShipped bool) {
	if !lifecycleShipped {
		s.lifecycle += len(b.lifecycle)
	}
	if !harnessToolShipped {
		s.harnessTool += len(b.harnessTool)
	}
	if !credentialShipped {
		s.credential += len(b.credential)
	}
	s.unknown += b.unknown
	s.malformed += b.malformed
}

func (s skippedRecords) log(logger *slog.Logger, path string) {
	if s.lifecycle > 0 {
		logger.Warn("audit collector skipped lifecycle records; no lifecycle flush route is configured", "path", path, "records", s.lifecycle)
	}
	if s.harnessTool > 0 {
		logger.Warn("audit collector skipped harness_tool records; no harness_tool flush route is configured", "path", path, "records", s.harnessTool)
	}
	if s.credential > 0 {
		logger.Warn("audit collector skipped credential records; no credential flush route is configured", "path", path, "records", s.credential)
	}
	if s.unknown > 0 {
		logger.Warn("audit collector skipped records with an unknown event_class", "path", path, "records", s.unknown)
	}
	if s.malformed > 0 {
		logger.Warn("audit collector skipped malformed records", "path", path, "records", s.malformed)
	}
}

func (c *Collector) flushBatch(ctx context.Context, b parsedBatch, skipped *skippedRecords) (int, error) {
	if len(b.decisions) > 0 && c.FlushClient != nil {
		payload, _ := json.Marshal(map[string][]DecisionEvent{"records": b.decisions})
		if _, err := c.FlushClient.Flush(ctx, b.decisions); err != nil {
			return 0, err
		}
		c.logger.Info("audit collector flush succeeded", "path", c.jsonlPath, "event_class", EventClassDecision, "records_sent", len(b.decisions), "payload_bytes", len(payload))
	}
	if len(b.lifecycle) > 0 && c.LifecycleClient != nil {
		payload, _ := json.Marshal(map[string][]json.RawMessage{"records": b.lifecycle})
		if _, err := c.LifecycleClient.FlushLifecycle(ctx, b.lifecycle); err != nil {
			return len(b.decisions), err
		}
		c.logger.Info("audit collector flush succeeded", "path", c.jsonlPath, "event_class", EventClassLifecycle, "events_sent", len(b.lifecycle), "payload_bytes", len(payload))
	}
	if len(b.harnessTool) > 0 && c.HarnessToolClient != nil {
		payload, _ := json.Marshal(map[string][]json.RawMessage{"records": b.harnessTool})
		if _, err := c.HarnessToolClient.FlushHarnessTool(ctx, b.harnessTool); err != nil {
			return len(b.decisions), err
		}
		c.logger.Info("audit collector flush succeeded", "path", c.jsonlPath, "event_class", EventClassHarnessTool, "events_sent", len(b.harnessTool), "payload_bytes", len(payload))
	}
	if len(b.harnessTool) > 0 && c.HarnessAuditClient != nil {
		n, err := c.HarnessAuditClient.FlushHarnessAudit(ctx, b.harnessTool)
		if err != nil {
			return len(b.decisions), err
		}
		c.logger.Info("audit collector flush succeeded", "path", c.jsonlPath, "event_class", EventClassHarnessTool, "route", "audit", "records_sent", len(b.harnessTool), "records_upserted", n)
	}
	if len(b.credential) > 0 && c.CredentialClient != nil {
		payload, _ := json.Marshal(map[string][]json.RawMessage{"records": b.credential})
		if _, err := c.CredentialClient.FlushCredential(ctx, b.credential); err != nil {
			return len(b.decisions), err
		}
		c.logger.Info("audit collector flush succeeded", "path", c.jsonlPath, "event_class", EventClassCredential, "events_sent", len(b.credential), "payload_bytes", len(payload))
	}
	skipped.add(b, c.LifecycleClient != nil, c.HarnessToolClient != nil || c.HarnessAuditClient != nil, c.CredentialClient != nil)
	return len(b.decisions), nil
}

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

type parsedBatch struct {
	decisions   []DecisionEvent
	lifecycle   []json.RawMessage
	harnessTool []json.RawMessage
	credential  []json.RawMessage
	unknown     int
	malformed   int
}

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
		class := EventClassDecision
		if probe.EventClass != nil {
			class = *probe.EventClass
		}
		switch class {
		case EventClassDecision:
			e, ok := ParseAuditLine(l)
			if !ok {
				out.malformed++
				continue
			}
			out.decisions = append(out.decisions, e)
		case EventClassLifecycle:
			out.lifecycle = append(out.lifecycle, json.RawMessage(raw))
		case EventClassHarnessTool:
			out.harnessTool = append(out.harnessTool, json.RawMessage(raw))
		case EventClassCredential:
			out.credential = append(out.credential, json.RawMessage(raw))
		default:
			out.unknown++
		}
	}
	return out
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	if parsed, err := time.Parse(time.RFC1123, value); err == nil {
		if d := parsed.Sub(now); d > 0 {
			return d
		}
		return 0
	}
	return 0
}

func StartCollector(ctx context.Context, cfg CollectorConfig, auditPath string, pollInterval, finalFlushTimeout time.Duration) (stop func()) {
	if auditPath == "" {
		return func() {}
	}
	audit := NewCollector(auditPath, NewABACFlushClientFromConfig(cfg, finalFlushTimeout), 100)
	audit.LifecycleClient = NewLifecycleFlushClientFromConfig(cfg, finalFlushTimeout)
	audit.HarnessToolClient = NewHarnessToolFlushClientFromConfig(cfg, finalFlushTimeout)
	audit.HarnessAuditClient = NewHarnessAuditFlushClientFromConfig(cfg, finalFlushTimeout)
	return collector.Service{
		Flusher:           audit,
		Path:              auditPath,
		PollInterval:      pollInterval,
		FinalFlushTimeout: finalFlushTimeout,
	}.Start(ctx)
}
