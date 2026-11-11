package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"sync"
	"time"
)

// HarnessAuditPath is the harness-tool spool under the runtime state
// directory. The kei-proxy hook appends to it when KEI_PROXY_AUDIT is unset,
// and the collector ships it from the same default.
func HarnessAuditPath(stateDir string) string {
	return filepath.Join(stateDir, "audit", "harness-tool.jsonl")
}

// ResolveAuditPath returns the configured audit spool (KEI_PROXY_AUDIT) or,
// when it is unset, the harness-tool spool under the runtime state directory.
func ResolveAuditPath(auditPath, stateDir string) string {
	if auditPath != "" || stateDir == "" {
		return auditPath
	}
	return HarnessAuditPath(stateDir)
}

// harnessAuditBatchMax is the catalog's cap on records per
// /api/v1/runtime/audit:flush request.
const harnessAuditBatchMax = 100

// HarnessAuditFlushClient ships harness_tool spool records to the audit log.
type HarnessAuditFlushClient interface {
	FlushHarnessAudit(ctx context.Context, records []json.RawMessage) (int, error)
}

// harnessAuditRecord is the HP harness audit event contract (2026-10-06): the
// only shape sent to /api/v1/runtime/audit:flush for a harness tool call. It is
// built field by field from the spool record, so tool_input, argv0, and any
// field added to the spool later can never be forwarded. Kei cannot decrypt
// args_ciphertext (ADR-030); it is passed through untouched.
type harnessAuditRecord struct {
	EventClass       string   `json:"event_class"`
	HarnessAgentID   string   `json:"harness_agent_id"`
	HarnessKind      string   `json:"harness_kind"`
	Tool             string   `json:"tool"`
	Skill            string   `json:"skill,omitempty"`
	Phase            string   `json:"phase"`
	NativeDecision   string   `json:"native_decision"`
	ArgsDigest       string   `json:"args_digest"`
	ResourcesTouched []string `json:"resources_touched,omitempty"`
	DigestKeyID      string   `json:"digest_key_id,omitempty"`
	ArgsCiphertext   string   `json:"args_ciphertext,omitempty"`
	RecipientKeyIDs  []string `json:"recipient_key_ids,omitempty"`
	HarnessSessionID string   `json:"harness_session_id,omitempty"`
	ToolUseID        string   `json:"tool_use_id,omitempty"`
	ObservedAt       string   `json:"observed_at"`
	// Caller metadata (HAI-527), the same columns the authorize path fills.
	// caller_origin is never set: no hook input says interactive or
	// automation, so it stays unknown.
	CallerHarness    string `json:"caller_harness,omitempty"`
	CallerSessionRef string `json:"caller_session_ref,omitempty"`
}

// hookCallerSessionRef is an opaque, stable reference to a harness session.
// The raw session id is hashed so the value always passes the catalog's
// caller_session_ref check (a record that fails it is dropped) and carries
// no harness-supplied text. Empty in, empty out (unknown).
func hookCallerSessionRef(sessionID string) string {
	if sessionID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(sessionID))
	return "session:" + hex.EncodeToString(sum[:16])
}

// spoolHarnessToolRecord decodes only the contract fields from a hook spool
// record. The hook writes the agent id as harness_id.
type spoolHarnessToolRecord struct {
	HarnessID        string   `json:"harness_id"`
	HarnessKind      string   `json:"harness_kind"`
	Tool             string   `json:"tool"`
	Skill            string   `json:"skill"`
	Phase            string   `json:"phase"`
	NativeDecision   string   `json:"native_decision"`
	ArgsDigest       string   `json:"args_digest"`
	ResourcesTouched []string `json:"resources_touched"`
	DigestKeyID      string   `json:"digest_key_id"`
	ArgsCiphertext   string   `json:"args_ciphertext"`
	RecipientKeyIDs  []string `json:"recipient_key_ids"`
	HarnessSessionID string   `json:"harness_session_id"`
	ToolUseID        string   `json:"tool_use_id"`
	ObservedAt       string   `json:"observed_at"`
}


// harnessAuditRecordFrom maps one spool record to the contract. Records that
// cannot satisfy the contract's required fields are rejected so a single bad
// line cannot hold the spool behind a permanent 400.
func harnessAuditRecordFrom(raw json.RawMessage) (harnessAuditRecord, bool) {
	var rec spoolHarnessToolRecord
	if json.Unmarshal(raw, &rec) != nil {
		return harnessAuditRecord{}, false
	}
	switch rec.HarnessKind {
	case "claude", "codex", "opencode", "cursor", "pi":
	default:
		return harnessAuditRecord{}, false
	}
	if rec.Tool == "" || rec.Phase == "" || rec.NativeDecision == "" || rec.ArgsDigest == "" || rec.ObservedAt == "" {
		return harnessAuditRecord{}, false
	}
	return harnessAuditRecord{
		EventClass:       EventClassHarnessTool,
		HarnessAgentID:   rec.HarnessID,
		HarnessKind:      rec.HarnessKind,
		Tool:             rec.Tool,
		Skill:            rec.Skill,
		Phase:            rec.Phase,
		NativeDecision:   rec.NativeDecision,
		ArgsDigest:       rec.ArgsDigest,
		ResourcesTouched: rec.ResourcesTouched,
		DigestKeyID:      rec.DigestKeyID,
		ArgsCiphertext:   rec.ArgsCiphertext,
		RecipientKeyIDs:  rec.RecipientKeyIDs,
		HarnessSessionID: rec.HarnessSessionID,
		ToolUseID:        rec.ToolUseID,
		ObservedAt:       rec.ObservedAt,
		CallerHarness:    canonicalHarnessKind(rec.HarnessKind),
		CallerSessionRef: hookCallerSessionRef(rec.HarnessSessionID),
	}, true
}

type harnessAuditFlushClient struct {
	baseURL     string
	path        string
	headers     map[string]string
	client      *http.Client
	requestMu   sync.Mutex
	nextRequest time.Time
}

type harnessAuditFlushHTTPError struct {
	statusCode int
	retryAfter time.Duration
}

func (e *harnessAuditFlushHTTPError) Error() string {
	return fmt.Sprintf("harness_tool audit flush returned status %d", e.statusCode)
}

// NewHarnessAuditFlushClientFromConfig returns nil without a runtime token:
// the audit:flush route authenticates the installation.
func NewHarnessAuditFlushClientFromConfig(cfg CollectorConfig, timeout time.Duration) HarnessAuditFlushClient {
	if cfg.Token() == "" {
		return nil
	}
	return &harnessAuditFlushClient{
		baseURL: cfg.ControlPlaneURL(),
		path:    "/api/v1/runtime/audit:flush",
		headers: map[string]string{"Authorization": "Bearer " + cfg.Token()},
		client:  &http.Client{Timeout: timeout},
	}
}

// FlushHarnessAudit maps each spool record to the contract and POSTs them in
// batches of at most harnessAuditBatchMax. Delivery is at-least-once: a failed
// batch returns an error so the collector keeps its cursor and retries.
func (c *harnessAuditFlushClient) FlushHarnessAudit(ctx context.Context, records []json.RawMessage) (int, error) {
	out := make([]harnessAuditRecord, 0, len(records))
	for _, raw := range records {
		if rec, ok := harnessAuditRecordFrom(raw); ok {
			out = append(out, rec)
		}
	}
	total := 0
	for start := 0; start < len(out); start += harnessAuditBatchMax {
		end := min(start+harnessAuditBatchMax, len(out))
		n, err := c.flushChunk(ctx, out[start:end])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func (c *harnessAuditFlushClient) flushChunk(ctx context.Context, records []harnessAuditRecord) (int, error) {
	body, err := json.Marshal(map[string][]harnessAuditRecord{"records": records})
	if err != nil {
		return 0, fmt.Errorf("marshal harness_tool audit flush: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+c.path, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("build harness_tool audit flush request: %w", err)
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
		return 0, fmt.Errorf("harness_tool audit flush request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		e := &harnessAuditFlushHTTPError{statusCode: resp.StatusCode}
		if resp.StatusCode == http.StatusTooManyRequests {
			e.retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())
		}
		return 0, e
	}
	var res struct {
		Upserted int `json:"upserted"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return 0, fmt.Errorf("decode harness_tool audit flush response: %w", err)
	}
	return res.Upserted, nil
}
