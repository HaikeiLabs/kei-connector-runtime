package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
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

// Collector ships pending JSONL decision events to ABAC. It records the number
// of lines already sent in a state file, so it is resumable across runs. Because
// the flush is idempotent (ABAC dedupes on span_id), re-sending an already
// flushed batch after a crash is safe.
type Collector struct {
	jsonlPath string
	statePath string
	abac      ABACFlushClient
	batchSize int
	logger    *slog.Logger
}

// NewCollector builds a collector for the given JSONL path. The state file
// defaults to <jsonlPath>.offset.
func NewCollector(jsonlPath string, abac ABACFlushClient, batchSize int) *Collector {
	if batchSize <= 0 {
		batchSize = 100
	}
	return &Collector{
		jsonlPath: jsonlPath,
		statePath: jsonlPath + ".offset",
		abac:      abac,
		batchSize: batchSize,
		logger:    slog.Default(),
	}
}

// Run flushes all pending records and returns how many were sent.
func (c *Collector) Run(ctx context.Context) (int, error) {
	sentCount, err := c.readSentCount()
	if err != nil {
		return 0, err
	}

	data, err := os.ReadFile(c.jsonlPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read jsonl: %w", err)
	}

	lines := splitLines(data)
	if len(lines) <= sentCount {
		return 0, nil
	}

	sent := 0
	for start := sentCount; start < len(lines); start += c.batchSize {
		end := start + c.batchSize
		if end > len(lines) {
			end = len(lines)
		}
		batch := parseBatch(lines[start:end])
		if len(batch) > 0 {
			if _, err := c.abac.Flush(ctx, batch); err != nil {
				return sent, err
			}
			sent += len(batch)
		}
		// Advance past every line in this batch (valid or malformed) so we never
		// re-send or re-parse them.
		sentCount = end
		if err := c.writeSentCount(sentCount); err != nil {
			return sent, err
		}
	}
	return sent, nil
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
				pending, oldestAge := c.pendingStats()
				c.logger.Info("audit collector ready", "path", c.jsonlPath, "records_flushed", sent, "pending_records", pending, "oldest_pending_age_seconds", oldestAge)
				readyLogged = true
			}
			retryDelay = 0
		} else {
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
			pending, oldestAge := c.pendingStats()
			c.logger.Error("audit collector flush failed; retaining spool and retrying", "path", c.jsonlPath, "retry_in", retryIn, "pending_records", pending, "oldest_pending_age_seconds", oldestAge, "error", err)
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
func (c *Collector) pendingStats() (int, int64) {
	sentCount, err := c.readSentCount()
	if err != nil {
		return 0, 0
	}
	data, err := os.ReadFile(c.jsonlPath)
	if err != nil {
		return 0, 0
	}
	lines := splitLines(data)
	if sentCount >= len(lines) {
		return 0, 0
	}

	pending := 0
	var oldest time.Time
	for _, line := range lines[sentCount:] {
		var event DecisionEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		pending++
		if event.InvokedAt.IsZero() {
			continue
		}
		if oldest.IsZero() || event.InvokedAt.Before(oldest) {
			oldest = event.InvokedAt
		}
	}
	if pending == 0 || oldest.IsZero() {
		return pending, 0
	}
	age := time.Since(oldest).Seconds()
	if age < 0 {
		age = 0
	}
	return pending, int64(age)
}

func (c *Collector) readSentCount() (int, error) {
	data, err := os.ReadFile(c.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read state: %w", err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("parse state: %w", err)
	}
	return n, nil
}

func (c *Collector) writeSentCount(n int) error {
	dir := filepath.Dir(c.statePath)
	tmp, err := os.CreateTemp(dir, filepath.Base(c.statePath)+".tmp-")
	if err != nil {
		return fmt.Errorf("create state temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	if err := tmp.Chmod(0o644); err != nil {
		return fmt.Errorf("chmod state temp file: %w", err)
	}
	if _, err := tmp.WriteString(strconv.Itoa(n)); err != nil {
		return fmt.Errorf("write state temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync state temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close state temp file: %w", err)
	}
	if err := os.Rename(tmpName, c.statePath); err != nil {
		return fmt.Errorf("replace state file: %w", err)
	}
	// Sync the directory so the rename itself survives a power loss.
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open state directory: %w", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync state directory: %w", err)
	}
	return nil
}

// splitLines splits raw JSONL into non-empty lines.
func splitLines(data []byte) []string {
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

// parseBatch decodes raw lines into events, dropping malformed lines.
func parseBatch(lines []string) []DecisionEvent {
	var out []DecisionEvent
	for _, l := range lines {
		var e DecisionEvent
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			continue
		}
		out = append(out, e)
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
	collector := NewCollector(*jsonlPath, client, *batchSize)
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
