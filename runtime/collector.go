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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/collector"
)

type ABACFlushClient interface {
	Flush(ctx context.Context, records []DecisionEvent) (DecisionFlushResult, error)
}

// DecisionFlushResult reports what one Flush call did with its records.
type DecisionFlushResult struct {
	Upserted int
	// Quarantined counts dropped records by reason code.
	Quarantined map[string]int
	// CatalogRejection is the catalog's error for the last rejected record
	// (status, reason, message). It never carries record contents.
	CatalogRejection string
}

func (r *DecisionFlushResult) quarantine(reason string, n int) {
	if r.Quarantined == nil {
		r.Quarantined = map[string]int{}
	}
	r.Quarantined[reason] += n
}

type abacFlushClient struct {
	baseURL string
	path    string
	headers map[string]string
	client  *http.Client
}

// NewABACFlushClientFromConfig flushes decision audit to the runtime control
// plane, authenticated with the installation token.
func NewABACFlushClientFromConfig(cfg CollectorConfig, timeout time.Duration) ABACFlushClient {
	return &abacFlushClient{
		baseURL: cfg.ControlPlaneURL(),
		path:    "/api/v1/runtime/audit:flush",
		headers: map[string]string{"Authorization": "Bearer " + cfg.Token()},
		client:  &http.Client{Timeout: timeout},
	}
}

// decisionFlushHTTPError carries the catalog's non-2xx for the audit:flush
// route: the status code, the Retry-After hint on a 429, and the AIP error
// body's status and message. The catalog's messages name the failed check,
// never a record's values.
type decisionFlushHTTPError struct {
	statusCode int
	retryAfter time.Duration
	status     string
	message    string
}

func (e *decisionFlushHTTPError) Error() string {
	msg := fmt.Sprintf("flush returned status %d", e.statusCode)
	if detail := e.detail(); detail != "" {
		msg += ": " + detail
	}
	return msg
}

func (e *decisionFlushHTTPError) detail() string {
	switch {
	case e.status != "" && e.message != "":
		return e.status + ": " + e.message
	default:
		return e.status + e.message
	}
}

// rejectsRecords reports whether the catalog refused the batch's contents, so
// splitting the batch can isolate the record at fault. Any other status
// (auth, throttling, outage) says nothing about the records and is retried
// whole.
func (e *decisionFlushHTTPError) rejectsRecords() bool {
	switch e.statusCode {
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
		return true
	}
	return false
}

func decisionFlushResponseError(resp *http.Response) error {
	e := &decisionFlushHTTPError{statusCode: resp.StatusCode}
	if resp.StatusCode == http.StatusTooManyRequests {
		e.retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())
	}
	var body struct {
		Error struct {
			Status  string `json:"status"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, maxCatalogErrorBody)).Decode(&body) == nil {
		e.status = safeCatalogErrorText(body.Error.Status)
		e.message = safeCatalogErrorText(body.Error.Message)
	}
	return e
}

// Flush POSTs the batch to the catalog's audit:flush route. Delivery is
// at-least-once: a failed batch returns an error so the collector retains the
// spool and retries.
//
// The catalog validates some record-level constraints across the whole batch
// and its 400 body names the failed check, not the record at fault (the
// audit_records handler answers "invalid request body" without pointing at a
// record), so one record the catalog will never accept — for example an empty
// invoking_subject on an older catalog build — would hold the spool forever
// (HAI-928). A batch the catalog rejects is therefore split in halves until
// each rejected record stands alone and is quarantined; the rest ship.
func (c *abacFlushClient) Flush(ctx context.Context, records []DecisionEvent) (DecisionFlushResult, error) {
	var res DecisionFlushResult
	if err := c.flushIsolatingRejects(ctx, records, &res); err != nil {
		return res, err
	}
	return res, nil
}

// flushIsolatingRejects sends records and, when the catalog rejects their
// contents, bisects them until each rejected record stands alone and is
// quarantined. Errors that are not record rejections are returned unchanged.
func (c *abacFlushClient) flushIsolatingRejects(ctx context.Context, records []DecisionEvent, res *DecisionFlushResult) error {
	n, err := c.flushChunk(ctx, records)
	if err == nil {
		res.Upserted += n
		return nil
	}
	var httpErr *decisionFlushHTTPError
	if !errors.As(err, &httpErr) || !httpErr.rejectsRecords() {
		return err
	}
	if len(records) == 1 {
		res.quarantine(quarantineCatalogRejected, 1)
		res.CatalogRejection = fmt.Sprintf("status %d %s", httpErr.statusCode, httpErr.detail())
		return nil
	}
	mid := len(records) / 2
	if err := c.flushIsolatingRejects(ctx, records[:mid], res); err != nil {
		return err
	}
	return c.flushIsolatingRejects(ctx, records[mid:], res)
}

func (c *abacFlushClient) flushChunk(ctx context.Context, records []DecisionEvent) (int, error) {
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

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return 0, decisionFlushResponseError(resp)
	}
	var out struct {
		Upserted *int `json:"upserted"`
		Received *int `json:"received"`
		Skipped  *int `json:"skipped"`
	}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&out); err != nil {
		return 0, fmt.Errorf("decode flush response: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return 0, errors.New("decode flush response: trailing data")
	}
	if out.Upserted == nil || out.Received == nil || out.Skipped == nil {
		return 0, errors.New("decode flush response: missing audit flush counts")
	}
	if *out.Upserted < 0 || *out.Skipped < 0 || *out.Received < 0 || *out.Upserted+*out.Skipped != *out.Received {
		return 0, fmt.Errorf("flush counts mismatch: upserted=%d skipped=%d received=%d", *out.Upserted, *out.Skipped, *out.Received)
	}
	if *out.Skipped != 0 {
		slog.Warn("audit collector skipped records acknowledged by catalog", "skipped", *out.Skipped)
	}
	return *out.Upserted, nil
}

type LifecycleFlushClient interface {
	FlushLifecycle(ctx context.Context, records []json.RawMessage) (int, error)
}

type HarnessToolFlushClient interface {
	FlushHarnessTool(ctx context.Context, records []json.RawMessage) (HarnessToolFlushResult, error)
}

// Quarantine reason codes for harness_tool records the catalog will never
// accept. A quarantined record is dropped from the spool and counted as loss.
const (
	quarantineMalformed       = "malformed"
	quarantineToolMissing     = "tool_missing"
	quarantineCatalogRejected = "catalog_rejected"
)

// HarnessToolFlushResult reports what one FlushHarnessTool call did with its
// records.
type HarnessToolFlushResult struct {
	Upserted int
	// Quarantined counts dropped records by reason code.
	Quarantined map[string]int
	// CatalogRejection is the catalog's error for the last rejected record
	// (status, reason, message). It never carries record contents.
	CatalogRejection string
}

func (r *HarnessToolFlushResult) quarantine(reason string, n int) {
	if r.Quarantined == nil {
		r.Quarantined = map[string]int{}
	}
	r.Quarantined[reason] += n
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
	var decisionErr *decisionFlushHTTPError
	if errors.As(err, &decisionErr) {
		return throttleDelay(decisionErr.statusCode, decisionErr.retryAfter)
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
	return &lifecycleFlushClient{
		baseURL: cfg.ControlPlaneURL(),
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
	// status and message come from the catalog's AIP error body. The
	// catalog's messages name the failed check, never an event's values.
	status  string
	message string
}

func (e *harnessToolFlushHTTPError) Error() string {
	msg := fmt.Sprintf("harness_tool flush returned status %d", e.statusCode)
	if detail := e.detail(); detail != "" {
		msg += ": " + detail
	}
	return msg
}

func (e *harnessToolFlushHTTPError) detail() string {
	switch {
	case e.status != "" && e.message != "":
		return e.status + ": " + e.message
	default:
		return e.status + e.message
	}
}

// rejectsRecords reports whether the catalog refused the batch's contents, so
// splitting the batch can isolate the record at fault. Any other status
// (auth, throttling, outage) says nothing about the records and is retried
// whole.
func (e *harnessToolFlushHTTPError) rejectsRecords() bool {
	switch e.statusCode {
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
		return true
	}
	return false
}

// maxCatalogErrorBody bounds how much of an error response is read.
const maxCatalogErrorBody = 4 << 10

// maxCatalogErrorText bounds each catalog error field carried into a log.
const maxCatalogErrorText = 200

func harnessToolFlushResponseError(resp *http.Response) error {
	e := &harnessToolFlushHTTPError{statusCode: resp.StatusCode}
	if resp.StatusCode == http.StatusTooManyRequests {
		e.retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())
	}
	var body struct {
		Error struct {
			Status  string `json:"status"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, maxCatalogErrorBody)).Decode(&body) == nil {
		e.status = safeCatalogErrorText(body.Error.Status)
		e.message = safeCatalogErrorText(body.Error.Message)
	}
	return e
}

// safeCatalogErrorText keeps a catalog error field printable and bounded
// before it reaches a log line.
func safeCatalogErrorText(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return -1
		}
		return r
	}, s)
	if len(s) > maxCatalogErrorText {
		s = s[:maxCatalogErrorText]
	}
	return s
}

func NewHarnessToolFlushClientFromConfig(cfg CollectorConfig, timeout time.Duration) HarnessToolFlushClient {
	if cfg.Token() == "" {
		return nil
	}
	return &harnessToolFlushClient{
		baseURL: cfg.ControlPlaneURL(),
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
//
// The catalog validates a batch all-or-nothing, so one bad record would hold
// the spool forever. A record that is not a tool observation (malformed, or
// no tool) is quarantined before sending, and a batch the catalog rejects is
// split until the rejected records are isolated and quarantined; the rest
// ship.
func (c *harnessToolFlushClient) FlushHarnessTool(ctx context.Context, records []json.RawMessage) (HarnessToolFlushResult, error) {
	var res HarnessToolFlushResult
	events := make([]harnessToolIngestEvent, 0, len(records))
	for _, raw := range records {
		var rec rawHarnessToolRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			res.quarantine(quarantineMalformed, 1)
			continue
		}
		if strings.TrimSpace(rec.Tool) == "" {
			res.quarantine(quarantineToolMissing, 1)
			continue
		}
		events = append(events, harnessToolIngestEvent{
			Tool:        rec.Tool,
			Skill:       rec.Skill,
			HarnessKind: canonicalHarnessKind(rec.HarnessKind),
			ObservedAt:  rec.ObservedAt,
		})
	}
	for start := 0; start < len(events); start += harnessToolBatchMax {
		end := start + harnessToolBatchMax
		if end > len(events) {
			end = len(events)
		}
		if err := c.flushIsolatingRejects(ctx, events[start:end], &res); err != nil {
			return res, err
		}
	}
	return res, nil
}

// flushIsolatingRejects sends events and, when the catalog rejects their
// contents, bisects them until each rejected event stands alone and is
// quarantined. Errors that are not record rejections are returned unchanged.
func (c *harnessToolFlushClient) flushIsolatingRejects(ctx context.Context, events []harnessToolIngestEvent, res *HarnessToolFlushResult) error {
	n, err := c.flushHarnessToolChunk(ctx, events)
	if err == nil {
		res.Upserted += n
		return nil
	}
	var httpErr *harnessToolFlushHTTPError
	if !errors.As(err, &httpErr) || !httpErr.rejectsRecords() {
		return err
	}
	if len(events) == 1 {
		res.quarantine(quarantineCatalogRejected, 1)
		res.CatalogRejection = fmt.Sprintf("status %d %s", httpErr.statusCode, httpErr.detail())
		return nil
	}
	mid := len(events) / 2
	if err := c.flushIsolatingRejects(ctx, events[:mid], res); err != nil {
		return err
	}
	return c.flushIsolatingRejects(ctx, events[mid:], res)
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
		skipped.moveQuarantined(st)
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
	// quarantined holds harness_tool records dropped since the collector
	// state was last written, by reason code.
	quarantined map[string]int
	// decisionQuarantined holds decision records dropped since the collector
	// state was last written, by reason code.
	decisionQuarantined map[string]int
}

func (s *skippedRecords) addQuarantined(counts map[string]int) {
	for reason, n := range counts {
		if s.quarantined == nil {
			s.quarantined = map[string]int{}
		}
		s.quarantined[reason] += n
	}
}

// addDecisionQuarantined accumulates decision records dropped because the
// catalog will never accept them, by reason code.
func (s *skippedRecords) addDecisionQuarantined(counts map[string]int) {
	for reason, n := range counts {
		if s.decisionQuarantined == nil {
			s.decisionQuarantined = map[string]int{}
		}
		s.decisionQuarantined[reason] += n
	}
}

// moveQuarantined adds the pending quarantine counts to the persisted loss
// totals and clears them, so each record is counted once.
func (s *skippedRecords) moveQuarantined(st *collectorState) {
	for reason, n := range s.quarantined {
		if st.HarnessToolQuarantined == nil {
			st.HarnessToolQuarantined = map[string]int64{}
		}
		st.HarnessToolQuarantined[reason] += int64(n)
	}
	s.quarantined = nil
	for reason, n := range s.decisionQuarantined {
		if st.DecisionQuarantined == nil {
			st.DecisionQuarantined = map[string]int64{}
		}
		st.DecisionQuarantined[reason] += int64(n)
	}
	s.decisionQuarantined = nil
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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
		res, err := c.FlushClient.Flush(ctx, b.decisions)
		if err != nil {
			return 0, err
		}
		c.logger.Info("audit collector flush succeeded", "path", c.jsonlPath, "event_class", EventClassDecision, "records_sent", len(b.decisions), "payload_bytes", len(payload))
		for _, reason := range sortedKeys(res.Quarantined) {
			c.logger.Warn("audit collector quarantined decision records the catalog will not accept",
				"path", c.jsonlPath, "reason", reason, "records", res.Quarantined[reason], "catalog_error", res.CatalogRejection)
		}
		skipped.addDecisionQuarantined(res.Quarantined)
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
		res, err := c.HarnessToolClient.FlushHarnessTool(ctx, b.harnessTool)
		if err != nil {
			return len(b.decisions), err
		}
		c.logger.Info("audit collector flush succeeded", "path", c.jsonlPath, "event_class", EventClassHarnessTool, "events_sent", len(b.harnessTool), "payload_bytes", len(payload))
		for _, reason := range sortedKeys(res.Quarantined) {
			c.logger.Warn("audit collector quarantined harness_tool records the catalog will not accept",
				"path", c.jsonlPath, "reason", reason, "records", res.Quarantined[reason], "catalog_error", res.CatalogRejection)
		}
		skipped.addQuarantined(res.Quarantined)
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
