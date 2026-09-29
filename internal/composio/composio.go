// Package composio is a SPIKE (HAI-142), not for production: a governed
// connector class that executes Composio tools with third-party-managed
// credentials. Kei authorizes and audits every call; Composio executes only
// after an allow. See docs/composio-spike.md.
//
// Composio holds the provider OAuth tokens (its connected accounts). The only
// tenant-side secret is the Composio project API key, resolved per call from
// the customer's secret manager through an opaque reference. Tool arguments
// and results transit, and by default are logged by, Composio.
package composio

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is Composio Cloud. Config cannot change it; only the
// Executor's test seam can.
const DefaultBaseURL = "https://backend.composio.dev"

// MaxInputBytes is the execution contract's input limit (16 KiB).
const MaxInputBytes = 16 << 10

var (
	ErrDisabled              = errors.New("composio connector is disabled")
	ErrDenied                = errors.New("kei denied the composio invocation")
	ErrInvalidInvocation     = errors.New("invalid composio invocation")
	ErrToolNotAllowed        = errors.New("capability is not on the composio allow-list")
	ErrActionMismatch        = errors.New("capability action mismatch")
	ErrApprovalRequired      = errors.New("mutating composio capability requires an approval")
	ErrSubjectNotMapped      = errors.New("subject has no composio user mapping")
	ErrCredentialUnavailable = errors.New("composio credential unavailable")
	ErrCredentialsRejected   = errors.New("composio rejected the project credentials")
	ErrRequestRejected       = errors.New("composio rejected the request")
	ErrNotFound              = errors.New("composio tool or connected account not found")
	ErrRateLimited           = errors.New("composio rate limit exceeded")
	ErrUnavailable           = errors.New("composio unavailable")
	ErrTimeout               = errors.New("composio request timed out")
	ErrResponseTooLarge      = errors.New("composio response exceeds configured limit")
	ErrToolFailed            = errors.New("composio tool execution failed")
)

// Invocation is one governed Composio call. Arguments are the tool input; they
// go to Composio but only their digest goes to audit.
type Invocation struct {
	Subject    string          `json:"subject"`
	Capability string          `json:"capability"`
	Action     string          `json:"action"`
	Resource   string          `json:"resource"`
	TraceID    string          `json:"trace_id"`
	ApprovalID string          `json:"approval_id,omitempty"`
	Arguments  json.RawMessage `json:"arguments,omitempty"`
}

// Decision is Kei's answer for an invocation. Only "allow" permits execution.
type Decision struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

// AuthorizeRequest is what Kei sees. It carries a digest of the input, never
// the input itself (connector execution contract §2), so the decision and any
// approval bind to the exact payload without the payload leaving the runtime.
type AuthorizeRequest struct {
	Subject     string `json:"subject"`
	Capability  string `json:"capability"`
	Action      string `json:"action"`
	Resource    string `json:"resource"`
	TraceID     string `json:"trace_id"`
	ApprovalID  string `json:"approval_id,omitempty"`
	InputDigest string `json:"input_digest"`
}

// Authorizer asks Kei for a decision. In the runtime this is the governed
// connector invoke path (/api/v1/data-connectors/invoke) or, once ADR-026
// bundles land, the local policy evaluator; any error is a deny.
type Authorizer interface {
	Authorize(context.Context, AuthorizeRequest) (Decision, error)
}

// CredentialResolver resolves an opaque secret reference. The runtime's
// SecretStoreCredentialResolver satisfies it.
type CredentialResolver interface {
	Resolve(context.Context, string) (string, error)
}

// Audit is the lineage for one Composio call. It never carries the API key,
// its reference, raw arguments, or result data.
type Audit struct {
	Subject         string `json:"subject"`
	Capability      string `json:"capability"`
	Action          string `json:"action"`
	Resource        string `json:"resource"`
	TraceID         string `json:"trace_id"`
	ApprovalID      string `json:"approval_id,omitempty"`
	ToolSlug        string `json:"tool_slug"`
	ToolVersion     string `json:"tool_version"`
	InputDigest     string `json:"input_digest"`
	ResultDigest    string `json:"result_digest,omitempty"`
	ResultBytes     int    `json:"result_bytes"`
	ComposioLogID   string `json:"composio_log_id,omitempty"`
	Outcome         string `json:"outcome"`
	CredentialClass string `json:"credential_class"`
}

// Result is the governed, size-capped, redacted Composio result.
type Result struct {
	Successful        bool            `json:"successful"`
	Data              json.RawMessage `json:"data,omitempty"`
	LogID             string          `json:"log_id,omitempty"`
	RetryAfterSeconds int             `json:"retry_after_seconds,omitempty"`
	Audit             Audit           `json:"audit"`
}

// Executor calls Composio's tool execution API. Client and BaseURL are test
// seams; production uses DefaultBaseURL.
type Executor struct {
	Config      Config
	Credentials CredentialResolver
	Client      *http.Client
	BaseURL     string
}

// GovernedInvoke is the only way to execute a Composio tool: Kei decides
// first, then the local allow-list, action, approval, and subject checks run,
// and only then does the request leave the runtime. Every failure is closed.
func GovernedInvoke(ctx context.Context, auth Authorizer, exec Executor, in Invocation) (*Result, error) {
	if !exec.Config.Enabled {
		return nil, ErrDisabled
	}
	if in.Subject == "" || in.Capability == "" || in.Action == "" || in.Resource == "" || in.TraceID == "" {
		return nil, ErrInvalidInvocation
	}
	input, digest, err := canonicalInput(in.Arguments)
	if err != nil {
		return nil, err
	}
	if auth == nil {
		return nil, ErrDenied
	}
	decision, err := auth.Authorize(ctx, AuthorizeRequest{
		Subject:     in.Subject,
		Capability:  in.Capability,
		Action:      in.Action,
		Resource:    in.Resource,
		TraceID:     in.TraceID,
		ApprovalID:  in.ApprovalID,
		InputDigest: digest,
	})
	if err != nil || decision.Decision != "allow" {
		return nil, ErrDenied
	}
	return exec.execute(ctx, in, input, digest)
}

// canonicalInput validates the input as a JSON object within MaxInputBytes and
// returns its canonical (sorted-key, compact) form and "sha256:<hex>" digest.
// It runs before any I/O. An empty input is the empty object.
func canonicalInput(raw json.RawMessage) (json.RawMessage, string, error) {
	if len(raw) > MaxInputBytes {
		return nil, "", ErrInvalidInvocation
	}
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return nil, "", ErrInvalidInvocation
	}
	canonical, err := json.Marshal(obj)
	if err != nil {
		return nil, "", ErrInvalidInvocation
	}
	return canonical, digestOf(canonical), nil
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (e Executor) execute(ctx context.Context, in Invocation, input json.RawMessage, digest string) (*Result, error) {
	tool, ok := e.Config.Tools[in.Capability]
	if !ok {
		return nil, ErrToolNotAllowed
	}
	if tool.Action != in.Action {
		return nil, ErrActionMismatch
	}
	if tool.Action != "read" && in.ApprovalID == "" {
		return nil, ErrApprovalRequired
	}
	userID, ok := e.Config.Subjects[in.Subject]
	if !ok || userID == "" {
		return nil, ErrSubjectNotMapped
	}
	res := &Result{Audit: Audit{
		Subject:         in.Subject,
		Capability:      in.Capability,
		Action:          in.Action,
		Resource:        in.Resource,
		TraceID:         in.TraceID,
		ApprovalID:      in.ApprovalID,
		ToolSlug:        tool.Slug,
		ToolVersion:     tool.Version,
		InputDigest:     digest,
		CredentialClass: CredentialLabel,
	}}

	if e.Credentials == nil {
		return nil, ErrCredentialUnavailable
	}
	apiKey, err := e.Credentials.Resolve(ctx, e.Config.APIKeyRef)
	if err != nil || apiKey == "" {
		return nil, ErrCredentialUnavailable
	}

	body, err := json.Marshal(map[string]any{
		"arguments": input,
		"user_id":   userID,
		"version":   tool.Version,
	})
	if err != nil {
		return nil, ErrInvalidInvocation
	}
	base := e.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	endpoint := strings.TrimRight(base, "/") + "/api/v3.1/tools/execute/" + url.PathEscape(tool.Slug)

	reqCtx, cancel := context.WithTimeout(ctx, time.Duration(e.Config.TimeoutMS)*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, ErrInvalidInvocation
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)

	client := e.Client
	if client == nil {
		client = &http.Client{}
	}
	// Tool execution can be a non-idempotent write: one attempt, no retries,
	// and no redirects that could carry the API key elsewhere.
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noRedirect.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			res.Audit.Outcome = "timeout"
			return res, ErrTimeout
		}
		res.Audit.Outcome = "unavailable"
		return res, ErrUnavailable
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, e.Config.ResponseMaxBytes+1))
	if err != nil {
		res.Audit.Outcome = "unavailable"
		return res, ErrUnavailable
	}
	if int64(len(raw)) > e.Config.ResponseMaxBytes {
		res.Audit.Outcome = "response_too_large"
		return res, ErrResponseTooLarge
	}

	if resp.StatusCode != http.StatusOK {
		return res, classifyStatus(resp, res)
	}

	var out struct {
		Data       json.RawMessage `json:"data"`
		Successful bool            `json:"successful"`
		LogID      string          `json:"log_id"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		res.Audit.Outcome = "malformed_response"
		return res, ErrUnavailable
	}
	res.LogID = out.LogID
	res.Audit.ComposioLogID = out.LogID
	if !out.Successful {
		// The provider's error text can carry tenant data; it stays out of
		// the error and the audit. Composio's log_id is the pointer to it.
		res.Audit.Outcome = "tool_failed"
		return res, ErrToolFailed
	}
	res.Successful = true
	res.Data = redact(out.Data, e.Config.RedactFields)
	res.Audit.ResultDigest = digestOf(res.Data)
	res.Audit.ResultBytes = len(res.Data)
	res.Audit.Outcome = "success"
	return res, nil
}

// ReasonCode maps an error from GovernedInvoke to the reason_code vocabulary of
// the proposed connector execution contract (kei-connector-runtime PR #44), so
// a Composio deny reads like any other provider's.
func ReasonCode(err error) string {
	switch {
	case errors.Is(err, ErrDisabled):
		return "provider_not_supported"
	case errors.Is(err, ErrDenied), errors.Is(err, ErrToolNotAllowed):
		return "policy_deny"
	case errors.Is(err, ErrInvalidInvocation), errors.Is(err, ErrActionMismatch):
		return "input_invalid"
	case errors.Is(err, ErrApprovalRequired):
		return "approval_required"
	case errors.Is(err, ErrSubjectNotMapped):
		return "oauth_not_connected"
	case errors.Is(err, ErrCredentialUnavailable):
		return "credential_unavailable"
	case errors.Is(err, ErrCredentialsRejected):
		return "provider_denied"
	case errors.Is(err, ErrNotFound):
		return "provider_not_found"
	case errors.Is(err, ErrRateLimited):
		return "provider_rate_limited"
	case errors.Is(err, ErrTimeout):
		return "provider_timeout"
	case errors.Is(err, ErrResponseTooLarge):
		return "result_too_large"
	default:
		return "provider_error"
	}
}

// classifyStatus maps Composio HTTP errors to stable errors that never echo
// the response body.
func classifyStatus(resp *http.Response, res *Result) error {
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		res.Audit.Outcome = "credentials_rejected"
		return ErrCredentialsRejected
	case resp.StatusCode == http.StatusTooManyRequests:
		res.Audit.Outcome = "rate_limited"
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
			res.RetryAfterSeconds = s
		}
		return ErrRateLimited
	case resp.StatusCode == http.StatusNotFound:
		res.Audit.Outcome = "not_found"
		return ErrNotFound
	case resp.StatusCode >= 500:
		res.Audit.Outcome = "unavailable"
		return ErrUnavailable
	default:
		res.Audit.Outcome = "request_rejected"
		return ErrRequestRejected
	}
}

// redact replaces every configured JSON field (case-insensitive, at any
// depth) with a sentinel. It mirrors redactResponseBody in the runtime's HTTP
// executor; a production version would share one implementation.
func redact(data json.RawMessage, fields []string) json.RawMessage {
	if len(fields) == 0 || len(data) == 0 {
		return data
	}
	var v any
	if json.Unmarshal(data, &v) != nil {
		return data
	}
	redactValue(v, fields)
	out, err := json.Marshal(v)
	if err != nil {
		return data
	}
	return out
}

func redactValue(v any, fields []string) {
	switch t := v.(type) {
	case map[string]any:
		for key, child := range t {
			matched := false
			for _, f := range fields {
				if strings.EqualFold(key, f) {
					t[key] = "[REDACTED]"
					matched = true
					break
				}
			}
			if !matched {
				redactValue(child, fields)
			}
		}
	case []any:
		for _, child := range t {
			redactValue(child, fields)
		}
	}
}
