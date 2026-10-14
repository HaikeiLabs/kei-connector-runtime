package mcproute

import (
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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/manifest"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
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
	// approved for this upstream. When non-empty, tools/list responses are
	ApprovedToolsHash string
}

// Config configures the /mcp/{slug} route handler.
type Config struct {
	// KeyRegistry validates route keys presented as Authorization Bearer tokens.
	// When nil, auth is skipped and every request is permitted.
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
	Code    int    `json:"code"`
	Message string `json:"message"`
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

// errAuthFailed is returned when the route key is missing or invalid.
const errAuthFailed = "invalid_route_key"

// ServeHTTP handles an MCP route request.
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

	sess := h.isValidRouteKey(r)
	if sess == nil {
		h.writeAuthError(w)
		return
	}

	if err := h.checkLoopback(r); err != nil {
		h.writeLoopbackError(w)
		return
	}

	upstream, ok := h.config.Upstreams[slug]
	if !ok {
		http.Error(w, "unknown connector", http.StatusNotFound)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
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
		if upstream.ApprovedToolsHash == "" {
			h.writeRPCError(w, id, -32000, "manifest_not_approved")
			return
		}
		tool := extractTool(req.Params)
		if tool == "" {
			h.writeRPCError(w, id, -32602, "missing tool name")
			return
		}
		if h.config.Authorizer == nil {
			h.writeRPCError(w, id, -32001, "not_implemented")
			return
		}
		// ADR-036 §4.5 steps 5-6: the slug must name an active mcp connector
		// in the workspace descriptors, and the session's agent must be bound
		// to it.
		descriptor, ok := h.lookupMCPDescriptor(slug)
		if !ok {
			h.writeRPCError(w, id, -32000, "connector_not_found")
			return
		}
		if !h.agentBound(sess.Agent, descriptor.ID) {
			h.writeRPCError(w, id, -32000, "connector_not_bound")
			return
		}
		if err := h.config.Authorizer.Authorize(r.Context(), Decision{
			SessionID:     sess.SessionID,
			Subject:       sess.Subject,
			Agent:         sess.Agent,
			HarnessKind:   sess.HarnessKind,
			ConnectorSlug: slug,
			Tool:          tool,
			Args:          req.Params,
		}); err != nil {
			var permErr *PermissionError
			if errors.As(err, &permErr) {
				h.writeRPCError(w, id, -32000, permErr.Reason)
				return
			}
			h.writeRPCError(w, id, -32000, "internal_error")
			return
		}
		listing := h.getVerifiedListing(slug)
		if listing == nil || !listing.toolNames[tool] {
			h.writeRPCError(w, id, -32000, "manifest_drift")
			return
		}
		h.forwardToUpstream(w, r, upstream, canonical, slug, sess)
	case "tools/list":
		if upstream.ApprovedToolsHash == "" {
			h.writeRPCError(w, id, -32000, "manifest_not_approved")
			return
		}
		listing, err := h.fetchAndVerifyManifest(r.Context(), upstream, slug, sess)
		if err != nil {
			h.config.Logger.Error("manifest drift", "error", err)
			h.writeError(w, http.StatusBadGateway, "manifest_drift")
			return
		}
		h.mu.Lock()
		h.listings[slug] = listing
		h.mu.Unlock()
		h.writeToolsList(w, id, h.filterTools(r.Context(), listing.tools, slug, sess))
	default:
		h.writeRPCError(w, id, -32601, "Method not found")
	}
}

func (h *Handler) forwardToUpstream(w http.ResponseWriter, r *http.Request, upstream UpstreamConfig, body []byte, slug string, sess *Session) {
	u, err := url.Parse(upstream.URL)
	if err != nil {
		h.config.Logger.Error("invalid upstream URL", "url", upstream.URL, "error", err)
		h.writeError(w, http.StatusBadGateway, "invalid_upstream_url")
		return
	}
	if err := h.checkSSRF(u); err != nil {
		h.config.Logger.Warn("ssrf block", "url", upstream.URL, "error", err)
		h.writeError(w, http.StatusBadGateway, "upstream_not_allowed")
		return
	}

	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upstream.URL, strings.NewReader(string(body)))
	if err != nil {
		h.config.Logger.Error("creating upstream request", "error", err)
		h.writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	upReq.Header.Set("Content-Type", "application/json")
	upReq.Header.Set("Accept", "application/json")
	if upstream.TokenSource != nil {
		token, err := upstream.TokenSource.Token(r.Context(), sess.Subject, slug)
		if err != nil {
			h.config.Logger.Warn("token_source_denied", "subject", sess.Subject, "slug", slug, "error", err)
			h.writeRPCError(w, nil, -32001, "internal_error")
			return
		}
		upReq.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := h.client.Do(upReq)
	if err != nil {
		if errors.Is(err, errSSRFBlocked) {
			h.writeError(w, http.StatusBadGateway, "upstream_not_allowed")
			return
		}
		h.config.Logger.Error("upstream request failed", "error", err)
		h.writeError(w, http.StatusBadGateway, "upstream_unreachable")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		h.config.Logger.Warn("upstream redirect", "status", resp.StatusCode, "slug", slug)
		h.writeError(w, http.StatusBadGateway, "upstream_redirect")
		return
	}

	contentType := resp.Header.Get("Content-Type")
	isSSE := strings.Contains(contentType, "text/event-stream")

	if !isSSE {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			h.config.Logger.Error("reading upstream response", "error", err)
			h.writeError(w, http.StatusBadGateway, "upstream_error")
			return
		}

		for k, v := range resp.Header {
			if len(v) > 0 {
				w.Header()[k] = v
			}
		}
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
		return
	}

	h.relaySSE(w, resp)
}

func (h *Handler) relaySSE(w http.ResponseWriter, resp *http.Response) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		h.config.Logger.Error("ResponseWriter does not support flushing")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	for k, v := range resp.Header {
		if len(v) > 0 {
			w.Header()[k] = v
		}
	}
	w.WriteHeader(resp.StatusCode)
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
			flusher.Flush()
		}
		if err != nil {
			break
		}
	}
	resp.Body.Close()
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
		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("reading upstream response: %w", err)
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
			return nil, fmt.Errorf("cannot parse tools/list response: %w", err)
		}
		if rpcResp.Error != nil {
			return nil, fmt.Errorf("upstream JSON-RPC error: %s", rpcResp.Error.Message)
		}
		if rpcResp.Result == nil || len(rpcResp.Result.Tools) == 0 {
			return nil, fmt.Errorf("empty tools list")
		}
		allTools = append(allTools, rpcResp.Result.Tools...)
		for _, t := range rpcResp.Result.Tools {
			totalBytes += len(t)
		}
		if len(allTools) > maxManifestTools {
			return nil, fmt.Errorf("manifest exceeds %d tools", maxManifestTools)
		}
		if totalBytes > maxManifestBytes {
			return nil, fmt.Errorf("manifest exceeds %d bytes", maxManifestBytes)
		}
		if rpcResp.Result.NextCursor == "" {
			break
		}
		cursor = rpcResp.Result.NextCursor
	}

	hsh, err := manifest.Hash(allTools)
	if err != nil {
		return nil, fmt.Errorf("cannot hash manifest: %w", err)
	}
	if hsh != upstream.ApprovedToolsHash {
		return nil, fmt.Errorf("manifest hash mismatch: got %s, want %s", hsh, upstream.ApprovedToolsHash)
	}

	toolNames := make(map[string]bool, len(allTools))
	for _, t := range allTools {
		var info struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(t, &info); err != nil {
			continue
		}
		toolNames[info.Name] = true
	}
	return &verifiedListing{hash: hsh, tools: allTools, toolNames: toolNames}, nil
}

// callUpstream makes one POST to the upstream MCP server and returns the
// response. The caller must close resp.Body.
func (h *Handler) callUpstream(ctx context.Context, upstream UpstreamConfig, slug string, sess *Session, body []byte) (*http.Response, error) {
	u, err := url.Parse(upstream.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %w", err)
	}
	if err := h.checkSSRF(u); err != nil {
		return nil, errSSRFBlocked
	}
	upReq, err := http.NewRequestWithContext(ctx, http.MethodPost, upstream.URL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating upstream request: %w", err)
	}
	upReq.Header.Set("Content-Type", "application/json")
	upReq.Header.Set("Accept", "application/json")
	if upstream.TokenSource != nil {
		token, err := upstream.TokenSource.Token(ctx, sess.Subject, slug)
		if err != nil {
			return nil, fmt.Errorf("token source: %w", err)
		}
		upReq.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := h.client.Do(upReq)
	if err != nil {
		if errors.Is(err, errSSRFBlocked) {
			return nil, errSSRFBlocked
		}
		return nil, fmt.Errorf("upstream request failed: %w", err)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		resp.Body.Close()
		return nil, fmt.Errorf("upstream redirect: %d", resp.StatusCode)
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

func (h *Handler) writeAuthError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(jsonrpcResponse{
		JSONRPC: "2.0",
		Error:   &jsonrpcError{Code: -31401, Message: errAuthFailed},
	})
}

func (h *Handler) checkLoopback(r *http.Request) error {
	if origin := r.Header.Get("Origin"); origin != "" {
		return errors.New("origin not allowed")
	}
	host := r.Host
	if host == "" {
		return nil
	}
	hOnly, _, _ := strings.Cut(host, ":")
	switch hOnly {
	case "127.0.0.1", "localhost", "::1", "":
		return nil
	default:
		return errors.New("non-loopback host")
	}
}

func (h *Handler) writeLoopbackError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(jsonrpcResponse{
		JSONRPC: "2.0",
		Error:   &jsonrpcError{Code: -31400, Message: "non_loopback_request"},
	})
}

func (h *Handler) writeRPCError(w http.ResponseWriter, id any, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jsonrpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &jsonrpcError{Code: code, Message: message},
	})
}

func (h *Handler) writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(jsonrpcResponse{
		JSONRPC: "2.0",
		Error:   &jsonrpcError{Code: -32000, Message: message},
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
