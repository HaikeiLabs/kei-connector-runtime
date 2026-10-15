package httpapi

// This file is the runtime-side implementation of the frozen HTTP API
// connector contract (docs/http-api-connector-contract.md). It deliberately
// has no URL or credential fields in the invocation, and it never writes
// credential material to an audit record or log. Every boundary is
// fail-closed: a missing resolver, a denied invocation, an unresolvable or
// reserved target, a cross-host redirect, an over-limit response, or a
// missing credential all abort the call with an error.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/credentials"
)

var (
	errHTTPResponseTooLarge = errors.New("HTTP response exceeds configured limit")
	errHTTPReservedTarget   = errors.New("HTTP target is reserved")
	errHTTPInvocationDenied = errors.New("HTTP invocation denied")
	errHTTPSSRFBlocked      = errors.New("HTTP address is reserved/blocked at dial")
)

// CredentialResolver resolves an opaque connector credential reference. An
// implementation may delegate to SecretStore or a control-plane-backed
// binding; callers never provide a secret literal to ExecuteHTTP.
type CredentialResolver interface {
	Resolve(context.Context, string) (string, error)
}

// SecretStoreCredentialResolver adapts the existing external secret-store
// boundary. The backend is deployment configuration; ref remains opaque
// metadata and is the only credential identifier accepted by this path.
type SecretStoreCredentialResolver struct {
	Store   credentials.Store
	Backend string
}

// Resolve validates the reference through the shared contract and the proxy's
// secret-store boundary before any backend I/O. A malformed reference or a
// backend failure yields a generic error that never echoes the reference.
func (r SecretStoreCredentialResolver) Resolve(ctx context.Context, ref string) (string, error) {
	if r.Store == nil || r.Backend == "" || contract.ValidateCredentialRef(ref) != nil {
		return "", errors.New("invalid credential reference")
	}
	value, err := r.Store.Get(ctx, r.Backend, ref)
	if err != nil || value == nil || *value == "" {
		return "", errors.New("credential unavailable")
	}
	return *value, nil
}

// HTTPExecutionAudit is the audit/trace lineage for one governed HTTP
// invocation. It preserves the full propagation chain — human subject, org,
// workspace, agent, connector, capability, action, resource, trace id, and
// trace id — and never carries credential material.
type HTTPExecutionAudit struct {
	Subject     string          `json:"subject"`
	OrgID       string          `json:"org_id"`
	WorkspaceID string          `json:"workspace_id"`
	AgentID     string          `json:"agent_id"`
	ConnectorID string          `json:"connector_id"`
	Capability  string          `json:"capability"`
	Action      contract.Action `json:"action"`
	Resource    string          `json:"resource"`
	TraceID     string          `json:"trace_id"`
}

// HTTPExecutionResult is the governed result of one invocation. Headers and
// body are already redacted; the audit carries the caller lineage.
type HTTPExecutionResult struct {
	StatusCode int                `json:"status_code"`
	Headers    http.Header        `json:"headers"`
	Body       []byte             `json:"body"`
	Audit      HTTPExecutionAudit `json:"audit"`
}

// HTTPExecutor is the governed runtime for provider-neutral HTTP API
// contract. Credentials is the only mandatory field; Client and LookupIP
// are injectable seams for tests.
type HTTPExecutor struct {
	Credentials CredentialResolver
	Client      *http.Client
	LookupIP    func(context.Context, string) ([]net.IP, error)
}

func executeHTTPInvocation(ctx context.Context, metadata contract.Metadata, in contract.Invocation, resolver CredentialResolver, client *http.Client) (*HTTPExecutionResult, error) {
	return (HTTPExecutor{Credentials: resolver, Client: client}).ExecuteHTTP(ctx, metadata, in)
}

// ExecuteHTTP enforces the full governed path: contract validation
// (method/path/query), credential-reference resolution, registered-host URL
// construction, SSRF target rejection, redirect policy, timeout and
// response-size limits, and output redaction. It fails closed at every step.
func (e HTTPExecutor) ExecuteHTTP(ctx context.Context, metadata contract.Metadata, in contract.Invocation) (*HTTPExecutionResult, error) {
	if e.Credentials == nil {
		return nil, errors.New("credential resolver is required")
	}
	// ValidateCall enforces the connector metadata, tenant/workspace scope,
	// active status, declared capability, action, and the HTTP invocation
	// boundary (method, relative path, query allowlist).
	if err := contract.ValidateCall(metadata, in); err != nil {
		return nil, fmt.Errorf("%w: %w", errHTTPInvocationDenied, err)
	}
	// The contract caps the request body too; the runtime re-checks before it
	// resolves a credential so an oversize body never reaches the provider.
	if int64(len(in.HTTP.Body)) > metadata.HTTPAPI.RequestMaxBytes {
		return nil, fmt.Errorf("%w: request body exceeds the configured limit", errHTTPInvocationDenied)
	}
	if err := contract.ValidateCredentialRef(metadata.CredentialRef); err != nil {
		return nil, errors.New("invalid credential reference")
	}
	secret, err := e.Credentials.Resolve(ctx, metadata.CredentialRef)
	if err != nil || secret == "" {
		return nil, errors.New("credential resolution failed")
	}

	h := metadata.HTTPAPI
	base, err := url.Parse(h.RegisteredBaseURL)
	if err != nil {
		return nil, errors.New("invalid registered base URL")
	}
	if err := e.checkHost(ctx, base.Hostname()); err != nil {
		return nil, err
	}

	// Join paths without allowing ResolveReference to discard the registered
	// base path. ValidateCall has already rejected traversal and URL syntax,
	// and the invocation carries only a relative path.
	joined := *base
	joined.Path = strings.TrimRight(base.Path, "/") + "/" + strings.TrimLeft(in.HTTP.Path, "/")
	joined.RawPath = ""
	q := url.Values{}
	for name, values := range in.HTTP.Query {
		for _, value := range values {
			q.Add(name, value)
		}
	}
	joined.RawQuery = q.Encode()

	timeout := time.Duration(h.TimeoutMS) * time.Millisecond
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// A bytes.Reader body lets a same-host 307/308 redirect replay it.
	var reqBody io.Reader
	if len(in.HTTP.Body) != 0 {
		reqBody = bytes.NewReader(in.HTTP.Body)
	}
	req, err := http.NewRequestWithContext(requestCtx, string(in.HTTP.Method), joined.String(), reqBody)
	if err != nil {
		return nil, errors.New("build HTTP request failed")
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", in.HTTP.ContentType)
	}
	value := secret
	if h.CredentialInjection.Scheme != "" {
		value = h.CredentialInjection.Scheme + " " + value
	}
	req.Header.Set(h.CredentialInjection.Name, value)

	client := e.Client
	if client == nil {
		client = &http.Client{}
	}
	copyClient := *client
	previousRedirect := client.CheckRedirect
	copyClient.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if !h.AllowRedirects {
			return http.ErrUseLastResponse
		}
		if len(via) >= h.MaxRedirects {
			return errors.New("HTTP redirect limit exceeded")
		}
		if !strings.EqualFold(r.URL.Hostname(), base.Hostname()) {
			return errors.New("cross-host HTTP redirect denied")
		}
		if err := e.checkHost(requestCtx, r.URL.Hostname()); err != nil {
			return err
		}
		if previousRedirect != nil {
			return previousRedirect(r, via)
		}
		return nil
	}

	resp, err := copyClient.Do(req)
	if err != nil {
		return nil, classifyHTTPError(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, h.ResponseMaxBytes+1))
	if err != nil {
		return nil, errors.New("read HTTP response failed")
	}
	if int64(len(body)) > h.ResponseMaxBytes {
		return nil, errHTTPResponseTooLarge
	}

	return &HTTPExecutionResult{
		StatusCode: resp.StatusCode,
		Headers:    redactHeaders(resp.Header, h.Redaction.Headers),
		Body:       redactResponseBody(body, h.Redaction.ResponseFields),
		Audit: HTTPExecutionAudit{
			Subject:     in.Subject,
			OrgID:       in.TenantID,
			WorkspaceID: in.WorkspaceID,
			AgentID:     in.AgentID,
			ConnectorID: in.ConnectorID,
			Capability:  in.Capability,
			Action:      in.Action,
			Resource:    in.Resource,
			TraceID:     in.TraceID,
		},
	}, nil
}

// classifyHTTPError maps transport failures to generic, stable messages. A
// deadline is reported as a timeout; every other failure is opaque so a
// provider's error never leaks into logs.
func classifyHTTPError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("HTTP request timed out")
	}
	return errors.New("HTTP request failed")
}

// checkHost resolves host and rejects the call if any resolved address is a
// reserved/private/metadata target. This is the SSRF boundary: the contract
// validates the registered hostname syntactically, and the runtime checks its
// actual DNS resolution.
func (e HTTPExecutor) checkHost(ctx context.Context, host string) error {
	lookup := e.LookupIP
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		}
	}
	ips, err := lookup(ctx, host)
	if err != nil || len(ips) == 0 {
		return errors.New("HTTP target could not be resolved")
	}
	for _, ip := range ips {
		if reservedIP(ip) {
			return errHTTPReservedTarget
		}
	}
	return nil
}

// reservedIP reports whether ip must never be a connector target. It covers
// loopback, private RFC1918, link-local (including the cloud metadata
// addresses), CGNAT, benchmark, and documentation ranges, plus the
// "this network" zero block, the future-use /4, and the NAT64 well-known
// prefix. IPv4-mapped IPv6 addresses are unwrapped by the caller before
// they reach this function.
func reservedIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 0 {
			return true
		}
		// 100.64.0.0/10 CGNAT
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
		// 198.18.0.0/15 benchmarking
		if ip4[0] == 198 && ip4[1] >= 18 && ip4[1] <= 19 {
			return true
		}
		// 192.0.0.0/24 IETF protocol assignments
		if ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 0 {
			return true
		}
		// 240.0.0.0/4 future use
		if ip4[0] >= 240 {
			return true
		}
		// Documentation ranges 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
		if ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2 {
			return true
		}
		if ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100 {
			return true
		}
		if ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113 {
			return true
		}
	}
	// 64:ff9b::/96 NAT64 well-known prefix
	if len(ip) == net.IPv6len && ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b {
		for i := 4; i < 12; i++ {
			if ip[i] != 0 {
				return false
			}
		}
		return true
	}
	return false
}

// redactHeaders clones headers and replaces every configured name's value with
// the sentinel, so credential or sensitive response headers never leave the
// governed path with their value intact.
func redactHeaders(headers http.Header, names []string) http.Header {
	out := headers.Clone()
	for _, name := range names {
		if out.Get(name) != "" {
			out.Set(name, "[REDACTED]")
		}
	}
	return out
}

// redactResponseBody replaces every configured JSON field with the sentinel.
// Non-JSON bodies are returned unchanged (there is no structured field to
// redact), and a body that fails to marshal back is also returned as-is.
func redactResponseBody(body []byte, fields []string) []byte {
	if len(fields) == 0 {
		return body
	}
	var value any
	if json.Unmarshal(body, &value) != nil {
		return body
	}
	redactJSON(value, fields)
	out, err := json.Marshal(value)
	if err != nil {
		return body
	}
	return out
}

func redactJSON(value any, fields []string) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			for _, field := range fields {
				if strings.EqualFold(key, field) {
					v[key] = "[REDACTED]"
					child = nil
					break
				}
			}
			if child != nil {
				redactJSON(child, fields)
			}
		}
	case []any:
		for _, child := range v {
			redactJSON(child, fields)
		}
	}
}

// defaultDialControl is the net.Dialer Control hook for the httpapi connector.
// It sees the resolved IP actually being dialed, closing the DNS rebinding /
// TOCTOU gap left by the URL-level checkHost.
func defaultDialControl(network, address string, c syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return errHTTPSSRFBlocked
	}
	ip := net.ParseIP(host)
	if ip == nil || reservedIP(ip) {
		return errHTTPSSRFBlocked
	}
	return nil
}

// GuardedHTTPTransport returns an *http.Transport that rejects any dial to
// a reserved/private IP. Use this instead of http.DefaultTransport so the
// SSRF guard runs at dial time, not just at host-resolution time.
func GuardedHTTPTransport() *http.Transport {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   defaultDialControl,
	}
	return &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext:           dialer.DialContext,
	}
}

// CheckHost applies the SSRF boundary to host: it fails when the name does
// not resolve or any resolved address is reserved. lookup nil means DNS.
func CheckHost(ctx context.Context, lookup func(context.Context, string) ([]net.IP, error), host string) error {
	return HTTPExecutor{LookupIP: lookup}.checkHost(ctx, host)
}
