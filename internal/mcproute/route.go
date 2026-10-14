package mcproute

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

// Catalog is the route's read-only view of the policy bundle in force: the
// installation workspace's v2 connector descriptors and agent bindings
// (ADR-036 §4.3). It is read on every request, so a bundle refresh takes
// effect without restarting the route.
type Catalog interface {
	// MCPConnector returns the mcp connector descriptor whose slug is slug
	// (§4.5 step 5). Its mcp block is set.
	MCPConnector(slug string) (policybundle.Connector, bool)
	// AgentBoundToConnector reports an agent_connector_bindings entry (step 6).
	AgentBoundToConnector(agentID, connectorID string) bool
	// MCPHosts returns host:port of every mcp descriptor URL: the only
	// destinations the upstream client may dial (§4.10).
	MCPHosts() []string
	// BundleDigest identifies the bundle in force. A change invalidates every
	// cached verified listing (§5.3).
	BundleDigest() string
}

// Config configures the /mcp/{slug} route handler.
type Config struct {
	// KeyRegistry validates route keys presented as Authorization Bearer tokens.
	// When nil, every request is rejected with invalid_route_key (fail closed).
	KeyRegistry *KeyRegistry
	// Authorizer decides whether a tool call or tool list entry is permitted.
	// When nil, every request is denied (fail-closed).
	Authorizer Authorizer
	// Logger for audit and errors. When nil, logs are discarded.
	Logger *slog.Logger
	// Catalog is the bundle in force. When nil, no connector is found and
	// nothing is dialed.
	Catalog Catalog
	// TokenSource provides the Bearer token sent upstream. When nil, no
	// Authorization header is set.
	TokenSource TokenSource
	// UpstreamTimeout bounds one upstream exchange, response body included
	// (ADR-036 §4.9). Zero means 60 s; values above 300 s are capped.
	UpstreamTimeout time.Duration
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

// Handler serves POST /mcp/{slug} by authenticating, authorizing tools/call,
// and forwarding to the upstream MCP server.
type Handler struct {
	config    Config
	client    *http.Client
	checkSSRF func(*url.URL) error
	dialCtl   func(network, address string, c syscall.RawConn) error
	now       func() time.Time
	mu        sync.Mutex
	listings  map[listingKey]*cachedListing
	// blocked records, per (session, connector), the approval under which
	// the upstream drifted.
	blocked map[listingKey]string
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
		now:       time.Now,
		listings:  make(map[listingKey]*cachedListing),
		blocked:   make(map[listingKey]string),
	}
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   func(network, address string, c syscall.RawConn) error { return h.dialCtl(network, address, c) },
	}
	h.client = &http.Client{
		Timeout: upstreamTimeout(cfg.UpstreamTimeout),
		Transport: &http.Transport{
			// Only hosts of approved mcp urls are dialed (§4.10); the
			// Control hook then checks the address actually connected to.
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if !h.egressAllowed(addr) {
					return nil, errEgressNotApproved
				}
				return dialer.DialContext(ctx, network, addr)
			},
		},
	}
	h.client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return h
}

// connector returns the bundle's mcp descriptor for slug (§4.5 step 5).
func (h *Handler) connector(slug string) (policybundle.Connector, bool) {
	if h.config.Catalog == nil {
		return policybundle.Connector{}, false
	}
	return h.config.Catalog.MCPConnector(slug)
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
	tool := extractTool(req.Params)
	if tool == "" {
		h.writeRPCError(w, id, -32602, "missing tool name")
		return
	}
	// Steps 5-6: the slug must name an active mcp connector in the workspace
	// descriptors, and the session's agent must be bound to it.
	d, ok := h.connector(slug)
	if !ok {
		writeDenial(w, http.StatusOK, id, codeDenied, reasonConnectorNotFound)
		return
	}
	if !h.config.Catalog.AgentBoundToConnector(sess.Agent, d.ID) {
		writeDenial(w, http.StatusOK, id, codeDenied, reasonConnectorNotBound)
		return
	}
	// Step 7: a verified listing that contains the tool.
	listing, err := h.verifiedListingFor(ctx, sess, d)
	if err != nil {
		h.denyUpstream(w, id, d, err)
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
	h.forwardToUpstream(w, ctx, id, d, canonical, sess)
}

// serveToolsList answers tools/list from the session's verified listing
// (ADR-036 §4.7). Drift returns no tools (§5.3).
func (h *Handler) serveToolsList(w http.ResponseWriter, ctx context.Context, id any, slug string, sess *Session) {
	d, ok := h.connector(slug)
	if !ok {
		writeDenial(w, http.StatusOK, id, codeDenied, reasonConnectorNotFound)
		return
	}
	if !h.config.Catalog.AgentBoundToConnector(sess.Agent, d.ID) {
		writeDenial(w, http.StatusOK, id, codeDenied, reasonConnectorNotBound)
		return
	}
	listing, err := h.verifiedListingFor(ctx, sess, d)
	var re *routeError
	if errors.As(err, &re) && re.reason == reasonManifestDrift {
		h.logUpstreamFailure(d, err)
		h.writeToolsList(w, id, []json.RawMessage{})
		return
	}
	if err != nil {
		h.denyUpstream(w, id, d, err)
		return
	}
	h.writeToolsList(w, id, h.filterTools(ctx, listing.tools, slug, sess))
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
