package mcproute

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/manifest"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
	"github.com/google/uuid"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

// Session carries the subject and metadata validated from a route key.
type Session struct {
	Subject     string
	Agent       string
	HarnessKind string
	SessionID   string // Kei session ID bound at key mint time
}

// Decision is the authorisation input for a single tool call or tool list entry.
type Decision struct {
	SessionID     string
	Subject       string
	Agent         string
	HarnessKind   string
	ConnectorSlug string
	Tool          string
	Args          json.RawMessage // nil for tools/list
}

// PermissionError is returned by an Authorizer when a tool call is denied.
type PermissionError struct {
	Reason string
	Tool   string
}

func (e *PermissionError) Error() string { return e.Reason + ": " + e.Tool }

// Authorizer decides whether a tool call is permitted.
type Authorizer interface {
	Authorize(ctx context.Context, d Decision) error
}

// TokenSource provides a per-request upstream Bearer token for a subject and
// connector slug. Called after authorize, before the upstream HTTP request.
// An error fail-closes the request: the upstream is never contacted and a
// JSON-RPC error is returned to the client. The returned token must never
// appear in log output.
type TokenSource interface {
	Token(ctx context.Context, subject, connectorSlug string) (string, error)
}

// StaticToken is a TokenSource that always returns the same fixed token.
type StaticToken string

func (t StaticToken) Token(_ context.Context, _, _ string) (string, error) {
	return string(t), nil
}

// UpstreamConfig configures a single upstream MCP server.
type UpstreamConfig struct {
	// URL is the upstream MCP server endpoint.
	URL string
	// TokenSource provides the Bearer token sent to the upstream MCP server.
	// When nil, no Authorization header is set.
	TokenSource TokenSource
	// ApprovedToolsHash is the approved manifest hash. Empty means no
	// manifest is approved yet (mcp_manifest_unapproved).
	ApprovedToolsHash string
}

// Config configures the /mcp/{slug} route handler.
type Config struct {
	// KeyRegistry validates route keys presented as Authorization Bearer tokens.
	// When nil, every request is rejected with invalid_route_key (fail closed).
	KeyRegistry *KeyRegistry
	// Authorizer decides whether a tool call or tool list entry is permitted.
	// When nil, every request is denied (fail-closed).
	Authorizer Authorizer
	// Upstreams maps connector slug to upstream MCP server config.
	Upstreams map[string]UpstreamConfig
	// Connectors are the installation workspace's v2 connector descriptors
	// (ADR-036 §4.3). The tools/call gate (§4.5 step 5) requires an mcp
	// descriptor whose slug matches the route slug.
	Connectors []policybundle.Connector
	// AgentBindings are the bundle's agent_connector_bindings (§4.5 step 6).
	AgentBindings []AgentBinding
	// Logger for audit and errors. When nil, logs are discarded.
	Logger *slog.Logger
	// UpstreamTimeout bounds one upstream exchange, response body included
	// (ADR-036 §4.9). Zero means 60 s; values above 300 s are capped.
	UpstreamTimeout time.Duration
}

// AgentBinding is one agent_connector_bindings entry (ADR-036 §4.5 step 6).
type AgentBinding struct {
	AgentID     string
	ConnectorID string
}

type jsonrpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonrpcError struct {
	Code    int           `json:"code"`
	Message string        `json:"message"`
	Data    *rpcErrorData `json:"data,omitempty"`
}

type jsonrpcResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      any           `json:"id"`
	Result  *any          `json:"result,omitempty"`
	Error   *jsonrpcError `json:"error,omitempty"`
}

// verifiedListing is a hash-verified tools/list result, cached per slug.
type verifiedListing struct {
	hash      string
	tools     []json.RawMessage
	toolNames map[string]bool
	// schemas holds each tool's verified inputSchema; compiled caches them.
	schemas  map[string]json.RawMessage
	schemaMu sync.Mutex
	compiled map[string]*jsonschema.Schema
}

// Handler serves POST /mcp/{slug} by authenticating, authorizing tools/call,
// and forwarding to the upstream MCP server.
type Handler struct {
	config    Config
	client    *http.Client
	checkSSRF func(*url.URL) error
	dialCtl   func(network, address string, c syscall.RawConn) error
	mu        sync.Mutex
	listings  map[string]*verifiedListing
}

// Size and time limits of the route (ADR-036 §4.5 step 2, §4.9).
const (
	maxRequestBytes        = 1 << 20
	maxResponseBytes       = 4 << 20
	defaultUpstreamTimeout = 60 * time.Second
	maxUpstreamTimeout     = 300 * time.Second
)

func upstreamTimeout(d time.Duration) time.Duration {
	switch {
	case d <= 0:
		return defaultUpstreamTimeout
	case d > maxUpstreamTimeout:
		return maxUpstreamTimeout
	default:
		return d
	}
}

// NewHandler creates a new MCP route handler.
func NewHandler(cfg Config) *Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	h := &Handler{
		config:    cfg,
		checkSSRF: checkSSRF,
		dialCtl:   defaultDialControl,
		listings:  make(map[string]*verifiedListing),
	}
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   func(network, address string, c syscall.RawConn) error { return h.dialCtl(network, address, c) },
	}
	h.client = &http.Client{
		Timeout: upstreamTimeout(cfg.UpstreamTimeout),
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
		},
	}
	h.client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return h
}

// lookupMCPDescriptor returns the mcp connector descriptor whose slug matches
// the route slug (ADR-036 §4.5 step 5).
func (h *Handler) lookupMCPDescriptor(slug string) (policybundle.Connector, bool) {
	for _, c := range h.config.Connectors {
		if c.Kind == "mcp" && c.Slug == slug {
			return c, true
		}
	}
	return policybundle.Connector{}, false
}

// agentBound reports whether the agent has an agent_connector_bindings entry
// for the connector (ADR-036 §4.5 step 6).
func (h *Handler) agentBound(agentID, connectorID string) bool {
	for _, b := range h.config.AgentBindings {
		if b.AgentID == agentID && b.ConnectorID == connectorID {
			return true
		}
	}
	return false
}

// ServeHTTP handles an MCP route request. Origin and Host are checked before
// the route key (ADR-036 §4.5 step 1), so a browser or rebound name never
// learns whether a key is valid.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/.well-known/") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	slug, ok := extractSlug(r.URL.Path)
	if !ok {
		http.Error(w, "invalid slug", http.StatusNotFound)
		return
	}

	if err := checkLoopback(r); err != nil {
		writeDenial(w, http.StatusForbidden, nil, codeDenied, reasonNonLoopback)
		return
	}

	sess := h.isValidRouteKey(r)
	if sess == nil {
		writeDenial(w, http.StatusForbidden, nil, codeUnauthenticated, errAuthFailed)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			h.writeRPCErrorStatus(w, http.StatusBadRequest, nil, -32600, "request_too_large")
			return
		}
		h.writeRPCErrorStatus(w, http.StatusBadRequest, nil, -32700, "Parse error")
		return
	}

	// Reject batch arrays (JSON-RPC batch not supported).
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '[' {
		h.writeRPCError(w, nil, -32601, "Method not found")
		return
	}

	var req jsonrpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		h.writeRPCError(w, nil, -32700, "Parse error")
		return
	}

	var id any
	json.Unmarshal(req.ID, &id)

	// Re-serialize to prevent duplicate-key attacks: Go's decoder uses the
	// last value for duplicate keys; raw forwarding could let an upstream
	// see a different value.
	canonical, err := json.Marshal(req)
	if err != nil {
		h.writeRPCError(w, id, -32603, "Internal error")
		return
	}

	switch req.Method {
	case "initialize":
		initializeResult := any(map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "serverInfo": map[string]any{"name": "kei-connector-runtime", "version": "1.0.0"}})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jsonrpcResponse{
			JSONRPC: "2.0",
			ID:      id,
			Result:  &initializeResult,
		})
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case "ping":
		pingResult := any(json.RawMessage("{}"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jsonrpcResponse{
			JSONRPC: "2.0",
			ID:      id,
			Result:  &pingResult,
		})
	case "tools/call":
		h.serveToolsCall(w, r.Context(), id, slug, sess, req, canonical)
	case "tools/list":
		h.serveToolsList(w, r.Context(), id, slug, sess)
	default:
		h.writeRPCError(w, id, -32601, "Method not found")
	}
}

// serveToolsCall runs ADR-036 §4.5 steps 5 to 11 for one tools/call. Every
// denial is answered before any request reaches the upstream server.
func (h *Handler) serveToolsCall(w http.ResponseWriter, ctx context.Context, id any, slug string, sess *Session, req jsonrpcRequest, canonical []byte) {
	upstream, ok := h.config.Upstreams[slug]
	if !ok {
		writeDenial(w, http.StatusOK, id, codeDenied, reasonConnectorNotFound)
		return
	}
	tool := extractTool(req.Params)
	if tool == "" {
		h.writeRPCError(w, id, -32602, "missing tool name")
		return
	}
	// Steps 5-6: the slug must name an active mcp connector in the workspace
	// descriptors, and the session's agent must be bound to it.
	descriptor, ok := h.lookupMCPDescriptor(slug)
	if !ok {
		writeDenial(w, http.StatusOK, id, codeDenied, reasonConnectorNotFound)
		return
	}
	if !h.agentBound(sess.Agent, descriptor.ID) {
		writeDenial(w, http.StatusOK, id, codeDenied, reasonConnectorNotBound)
		return
	}
	// Step 7: a verified listing that contains the tool.
	if upstream.ApprovedToolsHash == "" {
		writeDenial(w, http.StatusOK, id, codeManifest, reasonManifestUnapproved)
		return
	}
	listing := h.getVerifiedListing(slug)
	if listing == nil {
		writeDenial(w, http.StatusOK, id, codeManifest, reasonManifestDrift)
		return
	}
	if !listing.toolNames[tool] {
		writeDenial(w, http.StatusOK, id, codeManifest, reasonToolNotApproved)
		return
	}
	// Step 8: the arguments must validate against the verified inputSchema.
	if err := listing.validateArguments(tool, req.Params); err != nil {
		h.config.Logger.Info("mcp_invalid_arguments", "slug", slug, "tool", tool, "error", err)
		writeDenial(w, http.StatusOK, id, codeInvalidArgs, reasonInvalidArguments)
		return
	}
	// Step 9: policy.
	if h.config.Authorizer == nil {
		writeDenial(w, http.StatusOK, id, codeDenied, reasonNoMatchingPolicy)
		return
	}
	if err := h.config.Authorizer.Authorize(ctx, Decision{
		SessionID:     sess.SessionID,
		Subject:       sess.Subject,
		Agent:         sess.Agent,
		HarnessKind:   sess.HarnessKind,
		ConnectorSlug: slug,
		Tool:          tool,
		Args:          req.Params,
	}); err != nil {
		reason := reasonPolicyDenied
		var permErr *PermissionError
		if errors.As(err, &permErr) && permErr.Reason != "" {
			reason = permErr.Reason
		}
		writeDenial(w, http.StatusOK, id, codeDenied, reason)
		return
	}
	h.forwardToUpstream(w, ctx, id, upstream, canonical, slug, sess)
}

// serveToolsList answers tools/list from a freshly verified upstream
// listing (ADR-036 §4.7). Drift returns no tools (§5.3).
func (h *Handler) serveToolsList(w http.ResponseWriter, ctx context.Context, id any, slug string, sess *Session) {
	upstream, ok := h.config.Upstreams[slug]
	if !ok {
		writeDenial(w, http.StatusOK, id, codeDenied, reasonConnectorNotFound)
		return
	}
	if upstream.ApprovedToolsHash == "" {
		writeDenial(w, http.StatusOK, id, codeManifest, reasonManifestUnapproved)
		return
	}
	listing, err := h.fetchAndVerifyManifest(ctx, upstream, slug, sess)
	if err != nil {
		h.logUpstreamFailure(slug, upstream, err)
		var re *routeError
		if errors.As(err, &re) {
			writeDenial(w, http.StatusOK, id, re.code, re.reason)
			return
		}
		h.writeToolsList(w, id, []json.RawMessage{})
		return
	}
	h.mu.Lock()
	h.listings[slug] = listing
	h.mu.Unlock()
	h.writeToolsList(w, id, h.filterTools(ctx, listing.tools, slug, sess))
}

// forwardToUpstream sends one tools/call and relays the response. Only the
// route's own Content-Type is set: no upstream header reaches the harness.
func (h *Handler) forwardToUpstream(w http.ResponseWriter, ctx context.Context, id any, upstream UpstreamConfig, body []byte, slug string, sess *Session) {
	resp, err := h.callUpstream(ctx, upstream, slug, sess, body)
	if err != nil {
		h.denyUpstream(w, id, slug, upstream, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		h.denyUpstream(w, id, slug, upstream, upstreamFailure(reasonUpstreamProtocolError, fmt.Errorf("upstream status %d", resp.StatusCode)))
		return
	}

	if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		h.relaySSE(w, id, slug, upstream, resp.Body)
		return
	}

	respBody, err := readCapped(resp.Body, maxResponseBytes)
	if err != nil {
		h.denyUpstream(w, id, slug, upstream, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respBody)
}

// readCapped reads at most limit bytes. A longer body is response_too_large.
func readCapped(r io.Reader, limit int) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, transportError(err)
	}
	if len(b) > limit {
		return nil, upstreamFailure(reasonResponseTooLarge, fmt.Errorf("response exceeds %d bytes", limit))
	}
	return b, nil
}

// relaySSE relays an SSE response stream one complete event at a time. Once
// the events would exceed maxResponseBytes in total, the stream ends with a
// response_too_large error for the request instead (ADR-036 §4.9).
func (h *Handler) relaySSE(w http.ResponseWriter, id any, slug string, upstream UpstreamConfig, body io.Reader) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		h.config.Logger.Error("mcp_sse_flush_unsupported", "slug", slug)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)

	br := bufio.NewReaderSize(body, 64<<10)
	var event bytes.Buffer
	total := 0
	for {
		chunk, err := br.ReadSlice('\n')
		event.Write(chunk)
		if total+event.Len() > maxResponseBytes {
			h.endSSE(w, flusher, id, slug, upstream, upstreamFailure(reasonResponseTooLarge, fmt.Errorf("stream exceeds %d bytes", maxResponseBytes)))
			return
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			if event.Len() > 0 {
				w.Write(event.Bytes())
				flusher.Flush()
			}
			if !errors.Is(err, io.EOF) {
				h.endSSE(w, flusher, id, slug, upstream, transportError(err))
			}
			return
		}
		if line := bytes.TrimRight(chunk, "\r\n"); len(line) == 0 {
			w.Write(event.Bytes())
			flusher.Flush()
			total += event.Len()
			event.Reset()
		}
	}
}

// endSSE terminates a relayed stream with a JSON-RPC error event.
func (h *Handler) endSSE(w io.Writer, flusher http.Flusher, id any, slug string, upstream UpstreamConfig, re *routeError) {
	h.logUpstreamFailure(slug, upstream, re)
	msg, _ := json.Marshal(jsonrpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &jsonrpcError{Code: re.code, Message: re.reason, Data: &rpcErrorData{Reason: re.reason, DecisionID: uuid.NewString()}},
	})
	fmt.Fprintf(w, "event: message\ndata: %s\n\n", msg)
	flusher.Flush()
}

// denyUpstream answers a failed upstream exchange with its §4.5 code.
func (h *Handler) denyUpstream(w http.ResponseWriter, id any, slug string, upstream UpstreamConfig, err error) {
	h.logUpstreamFailure(slug, upstream, err)
	re := upstreamFailure(reasonUpstreamUnreachable, err)
	errors.As(err, &re)
	writeDenial(w, http.StatusOK, id, re.code, re.reason)
}

// logUpstreamFailure logs the connector slug and upstream host, never the
// URL: its path or query can hold a secret.
func (h *Handler) logUpstreamFailure(slug string, upstream UpstreamConfig, err error) {
	h.config.Logger.Warn("mcp_upstream_failed", "slug", slug, "upstream_host", upstreamHost(upstream.URL), "error", err)
}

func upstreamHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// maxManifestTools and maxManifestBytes cap the verified manifest size.
const (
	maxManifestTools = 512
	maxManifestBytes = 4 * 1024 * 1024
)

func (h *Handler) getVerifiedListing(slug string) *verifiedListing {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.listings[slug]
}

// fetchAndVerifyManifest pages through the upstream tools/list, fails closed
// on upstream errors, empty lists, or exceeding the manifest caps, and
// verifies the concatenated hash against the approved hash.
func (h *Handler) fetchAndVerifyManifest(ctx context.Context, upstream UpstreamConfig, slug string, sess *Session) (*verifiedListing, error) {
	var allTools []json.RawMessage
	totalBytes := 0
	cursor := ""
	for {
		var params json.RawMessage
		if cursor != "" {
			b, err := json.Marshal(map[string]string{"cursor": cursor})
			if err != nil {
				return nil, fmt.Errorf("cannot marshal cursor params: %w", err)
			}
			params = b
		}
		body, err := json.Marshal(jsonrpcRequest{
			JSONRPC: "2.0",
			ID:      json.RawMessage("1"),
			Method:  "tools/list",
			Params:  params,
		})
		if err != nil {
			return nil, fmt.Errorf("cannot marshal tools/list request: %w", err)
		}
		resp, err := h.callUpstream(ctx, upstream, slug, sess, body)
		if err != nil {
			return nil, err
		}
		respBody, err := readCapped(resp.Body, maxResponseBytes)
		resp.Body.Close()
		var re *routeError
		if errors.As(err, &re) && re.reason == reasonResponseTooLarge {
			// §4.7 step 1: a listing above 4 MiB is drift, not an upstream error.
			return nil, fmt.Errorf("%w: manifest exceeds %d bytes", errManifestDrift, maxManifestBytes)
		}
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return nil, upstreamFailure(reasonUpstreamProtocolError, fmt.Errorf("upstream status %d", resp.StatusCode))
		}
		var rpcResp struct {
			Result *struct {
				Tools      []json.RawMessage `json:"tools"`
				NextCursor string            `json:"nextCursor,omitempty"`
			} `json:"result"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(respBody, &rpcResp); err != nil {
			return nil, upstreamFailure(reasonUpstreamProtocolError, fmt.Errorf("cannot parse tools/list response: %w", err))
		}
		if rpcResp.Error != nil {
			return nil, upstreamFailure(reasonUpstreamProtocolError, errors.New("upstream answered tools/list with a JSON-RPC error"))
		}
		if rpcResp.Result == nil || len(rpcResp.Result.Tools) == 0 {
			return nil, fmt.Errorf("%w: empty tools list", errManifestDrift)
		}
		allTools = append(allTools, rpcResp.Result.Tools...)
		for _, t := range rpcResp.Result.Tools {
			totalBytes += len(t)
		}
		if len(allTools) > maxManifestTools {
			return nil, fmt.Errorf("%w: manifest exceeds %d tools", errManifestDrift, maxManifestTools)
		}
		if totalBytes > maxManifestBytes {
			return nil, fmt.Errorf("%w: manifest exceeds %d bytes", errManifestDrift, maxManifestBytes)
		}
		if rpcResp.Result.NextCursor == "" {
			break
		}
		cursor = rpcResp.Result.NextCursor
	}

	hsh, err := manifest.Hash(allTools)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid manifest: %v", errManifestDrift, err)
	}
	if hsh != upstream.ApprovedToolsHash {
		return nil, fmt.Errorf("%w: manifest hash %s is not the approved %s", errManifestDrift, hsh, upstream.ApprovedToolsHash)
	}

	return newVerifiedListing(hsh, allTools)
}

// newVerifiedListing indexes a listing whose hash has been verified.
func newVerifiedListing(hash string, tools []json.RawMessage) (*verifiedListing, error) {
	toolNames := make(map[string]bool, len(tools))
	schemas := make(map[string]json.RawMessage, len(tools))
	for _, t := range tools {
		var info struct {
			Name        string          `json:"name"`
			InputSchema json.RawMessage `json:"inputSchema"`
		}
		if err := json.Unmarshal(t, &info); err != nil {
			continue
		}
		toolNames[info.Name] = true
		schemas[info.Name] = info.InputSchema
	}
	return &verifiedListing{hash: hash, tools: tools, toolNames: toolNames, schemas: schemas}, nil
}

// callUpstream makes one POST to the upstream MCP server and returns the
// response. The caller must close resp.Body. Every error is a *routeError
// that never names the upstream URL. A 3xx is never followed (§4.10).
func (h *Handler) callUpstream(ctx context.Context, upstream UpstreamConfig, slug string, sess *Session, body []byte) (*http.Response, error) {
	u, err := url.Parse(upstream.URL)
	if err != nil {
		return nil, upstreamFailure(reasonUpstreamBlocked, errors.New("invalid upstream URL"))
	}
	if err := h.checkSSRF(u); err != nil {
		return nil, upstreamFailure(reasonUpstreamBlocked, errSSRFBlocked)
	}
	upReq, err := http.NewRequestWithContext(ctx, http.MethodPost, upstream.URL, bytes.NewReader(body))
	if err != nil {
		return nil, upstreamFailure(reasonUpstreamBlocked, errors.New("cannot build upstream request"))
	}
	upReq.Header.Set("Content-Type", "application/json")
	upReq.Header.Set("Accept", "application/json")
	if upstream.TokenSource != nil {
		token, err := upstream.TokenSource.Token(ctx, sess.Subject, slug)
		if err != nil {
			return nil, &routeError{code: codeCredential, reason: reasonCredentialUnavailable, err: err}
		}
		upReq.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := h.client.Do(upReq)
	if err != nil {
		return nil, transportError(err)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		resp.Body.Close()
		return nil, upstreamFailure(reasonUpstreamProtocolError, fmt.Errorf("upstream redirect %d not followed", resp.StatusCode))
	}
	return resp, nil
}

// filterTools removes tools the Authorizer denies. A nil Authorizer denies
// every tool (fail-closed).
func (h *Handler) filterTools(ctx context.Context, tools []json.RawMessage, slug string, sess *Session) []json.RawMessage {
	if h.config.Authorizer == nil {
		return []json.RawMessage{}
	}
	filtered := make([]json.RawMessage, 0, len(tools))
	for _, t := range tools {
		var info struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(t, &info); err != nil {
			continue
		}
		if err := h.config.Authorizer.Authorize(ctx, Decision{
			SessionID:     sess.SessionID,
			Subject:       sess.Subject,
			Agent:         sess.Agent,
			HarnessKind:   sess.HarnessKind,
			ConnectorSlug: slug,
			Tool:          info.Name,
		}); err != nil {
			continue
		}
		filtered = append(filtered, t)
	}
	return filtered
}

func (h *Handler) writeToolsList(w http.ResponseWriter, id any, tools []json.RawMessage) {
	result := any(map[string]any{"tools": tools})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jsonrpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  &result,
	})
}

var errSSRFBlocked = errors.New("ssrf: address not allowed")

// errManifestDrift marks a listing that cannot be verified against the
// approval (ADR-036 §5.3).
var errManifestDrift = errors.New(reasonManifestDrift)

// blockedNets are extra ranges rejected by the dial Control hook in addition
// to loopback, private, link-local, unspecified, and multicast addresses.
var blockedNets = func() []*net.IPNet {
	cidrs := []string{
		"0.0.0.0/8",
		"192.0.0.0/24",
		"198.18.0.0/15",
		"240.0.0.0/4",
		"64:ff9b::/96",
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("mcproute: invalid blocked CIDR " + c + ": " + err.Error())
		}
		nets = append(nets, n)
	}
	return nets
}()

// isBlockedIP reports whether ip must not be dialed by the upstream client.
func isBlockedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	for _, n := range blockedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// defaultDialControl is the net.Dialer Control hook for the upstream client.
// It sees the resolved IP actually being dialed, closing the DNS rebinding /
// TOCTOU gap left by the URL-level check.
func defaultDialControl(network, address string, c syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return errSSRFBlocked
	}
	ip := net.ParseIP(host)
	if ip == nil || isBlockedIP(ip) {
		return errSSRFBlocked
	}
	return nil
}

func checkSSRF(u *url.URL) error {
	if u.Scheme != "https" {
		return errSSRFBlocked
	}
	if u.User != nil {
		return errSSRFBlocked
	}
	host := u.Hostname()
	ips, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("dns resolution failed: %w", err)
	}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if isBlockedIP(ip) || isCGNAT(ip) {
			return errSSRFBlocked
		}
	}
	return nil
}

func isCGNAT(ip net.IP) bool {
	if ip.To4() == nil {
		return false
	}
	// 100.64.0.0/10
	cgnat := net.IPNet{
		IP:   net.IPv4(100, 64, 0, 0),
		Mask: net.CIDRMask(10, 32),
	}
	return cgnat.Contains(ip)
}

func (h *Handler) isValidRouteKey(r *http.Request) *Session {
	if h.config.KeyRegistry == nil {
		return nil
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return nil
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	sess, ok := h.config.KeyRegistry.Validate(token)
	if !ok {
		return nil
	}
	return sess
}

// checkLoopback enforces ADR-036 §4.4 rule 2: no Origin header, and a Host
// of 127.0.0.1, localhost or [::1] with a port.
func checkLoopback(r *http.Request) error {
	if _, ok := r.Header["Origin"]; ok {
		return errors.New("origin not allowed")
	}
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		return errors.New("host must name a loopback address and port")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return errors.New("invalid host port")
	}
	switch host {
	case "127.0.0.1", "localhost", "::1":
		return nil
	default:
		return errors.New("non-loopback host")
	}
}

func (h *Handler) writeRPCError(w http.ResponseWriter, id any, code int, message string) {
	h.writeRPCErrorStatus(w, http.StatusOK, id, code, message)
}

func (h *Handler) writeRPCErrorStatus(w http.ResponseWriter, status int, id any, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(jsonrpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &jsonrpcError{Code: code, Message: message},
	})
}

func extractSlug(path string) (string, bool) {
	if !strings.HasPrefix(path, "/mcp/") {
		return "", false
	}
	slug := strings.TrimPrefix(path, "/mcp/")
	if idx := strings.IndexByte(slug, '/'); idx >= 0 {
		slug = slug[:idx]
	}
	if slug == "" || strings.ContainsAny(slug, "/?#") {
		return "", false
	}
	return slug, true
}

func extractTool(params json.RawMessage) string {
	if len(params) == 0 {
		return ""
	}
	var p struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ""
	}
	return p.Name
}
