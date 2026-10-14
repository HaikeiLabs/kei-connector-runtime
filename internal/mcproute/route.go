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
	"github.com/google/uuid"
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

// Verdict is what the policy decision rests on, for audit (ADR-036 §4.9).
type Verdict struct {
	PolicyID      string
	BundleVersion int64
	DenySource    string
	// Groups are the session subject's groups the decision used.
	Groups []string
}

// Authorizer decides whether a tool call is permitted. A denial is a
// *PermissionError; the Verdict is returned either way.
type Authorizer interface {
	Authorize(ctx context.Context, d Decision) (Verdict, error)
}

// ConnectorCredential is a connector's token released for a session, with
// the audience recorded for it (HAI-577).
type ConnectorCredential struct {
	ConnectorID, Issuer, Resource, AccountModel, AccessToken string
}

// CredentialSource resolves the session's credential for an mcp connector
// and its canonical resource (ADR-036 §4.8).
type CredentialSource interface {
	UseCredential(ctx context.Context, sess *Session, connectorID, resource string, fn func(ConnectorCredential) error) error
	Discard(sess *Session, connectorID, resource string)
}

// CredentialDenied is why the session has no credential for a connector:
// a credential release reason such as AUDIENCE_MISMATCH or NOT_CONNECTED.
type CredentialDenied struct{ Reason string }

func (e *CredentialDenied) Error() string { return "credential denied: " + e.Reason }

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
	// Submitter receives observed manifests the route cannot verify
	// (§5.4). When nil, nothing is submitted.
	Submitter ManifestSubmitter
	// Auditor receives one record per tools/list and tools/call (§4.9).
	// When nil, nothing is recorded.
	Auditor Auditor
	// Catalog is the bundle in force. When nil, no connector is found and
	// nothing is dialed.
	Catalog     Catalog
	Credentials CredentialSource
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
	// submitted holds the (connector, manifest_hash) candidates submitted;
	// submits tracks submissions in flight.
	submitted map[string]bool
	submits   sync.WaitGroup
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
		submitted: make(map[string]bool),
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

	// Step 2: the request metadata headers must agree with the body.
	if code, message := checkRequestHeaders(r.Header, req); code != 0 {
		h.writeRPCErrorStatus(w, http.StatusBadRequest, id, code, message)
		return
	}

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
		initializeResult := any(map[string]any{
			"protocolVersion": negotiateProtocolVersion(req.Params),
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "kei-connector-runtime", "version": "1.0.0"},
		})
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
// denial is answered before any request reaches the upstream server, and the
// call writes exactly one audit record (§4.9).
func (h *Handler) serveToolsCall(w http.ResponseWriter, ctx context.Context, id any, slug string, sess *Session, req jsonrpcRequest, canonical []byte) {
	rec := h.newAudit("mcp.tools_call", slug, sess)
	defer h.emit(ctx, rec)
	tool := extractTool(req.Params)
	if tool == "" {
		rec.ReasonCode = "invalid_request"
		h.writeRPCError(w, id, -32602, "missing tool name")
		return
	}
	rec.Tool, rec.Args = tool, extractArguments(req.Params)
	// Steps 5-6: the slug must name an active mcp connector in the workspace
	// descriptors, and the session's agent must be bound to it.
	d, ok := h.connector(slug)
	if !ok {
		h.deny(w, rec, id, codeDenied, reasonConnectorNotFound)
		return
	}
	rec.describe(d)
	if !h.config.Catalog.AgentBoundToConnector(sess.Agent, d.ID) {
		h.deny(w, rec, id, codeDenied, reasonConnectorNotBound)
		return
	}
	// Step 7: a verified listing that contains the tool.
	listing, err := h.verifiedListingFor(ctx, sess, d)
	if err != nil {
		h.denyUpstream(w, rec, id, d, err)
		return
	}
	if !listing.toolNames[tool] {
		h.deny(w, rec, id, codeManifest, reasonToolNotApproved)
		return
	}
	// Step 8: the arguments must validate against the verified inputSchema.
	if err := listing.validateArguments(tool, req.Params); err != nil {
		h.config.Logger.Info("mcp_invalid_arguments", "slug", slug, "tool", tool, "error", err)
		h.deny(w, rec, id, codeInvalidArgs, reasonInvalidArguments)
		return
	}
	// Step 9: policy.
	if h.config.Authorizer == nil {
		h.deny(w, rec, id, codeDenied, reasonNoMatchingPolicy)
		return
	}
	verdict, err := h.config.Authorizer.Authorize(ctx, Decision{
		SessionID:     sess.SessionID,
		Subject:       sess.Subject,
		Agent:         sess.Agent,
		HarnessKind:   sess.HarnessKind,
		ConnectorSlug: slug,
		Tool:          tool,
		Args:          req.Params,
	})
	rec.PolicyID, rec.BundleVersion, rec.DenySource, rec.Groups = verdict.PolicyID, verdict.BundleVersion, verdict.DenySource, verdict.Groups
	if err != nil {
		reason := reasonPolicyDenied
		var permErr *PermissionError
		if errors.As(err, &permErr) && permErr.Reason != "" {
			reason = permErr.Reason
		}
		h.deny(w, rec, id, codeDenied, reason)
		return
	}
	rec.Decision = "allow"
	h.forwardToUpstream(w, ctx, rec, id, d, canonical, sess)
}

// serveToolsList answers tools/list from the session's verified listing
// (ADR-036 §4.7). Drift returns no tools (§5.3). It writes one audit record
// with the listed, hidden and unapproved counts.
func (h *Handler) serveToolsList(w http.ResponseWriter, ctx context.Context, id any, slug string, sess *Session) {
	rec := h.newAudit("mcp.tools_list", slug, sess)
	defer h.emit(ctx, rec)
	d, ok := h.connector(slug)
	if !ok {
		h.deny(w, rec, id, codeDenied, reasonConnectorNotFound)
		return
	}
	rec.describe(d)
	if !h.config.Catalog.AgentBoundToConnector(sess.Agent, d.ID) {
		h.deny(w, rec, id, codeDenied, reasonConnectorNotBound)
		return
	}
	if d.MCP.ApprovedManifestHash == "" {
		// §5.3: no approval yet. Observe the listing so it can be submitted
		// as a candidate; nothing from it reaches the harness.
		if tools, err := h.fetchListing(ctx, d, sess); err == nil {
			rec.Unapproved = len(tools)
			h.submitCandidate(d, tools)
		}
		h.deny(w, rec, id, codeManifest, reasonManifestUnapproved)
		return
	}
	listing, err := h.verifiedListingFor(ctx, sess, d)
	var re *routeError
	if errors.As(err, &re) && re.reason == reasonManifestDrift {
		h.logUpstreamFailure(d, err)
		rec.Decision, rec.ReasonCode, rec.Unapproved = "deny", reasonManifestDrift, unapprovedCount(err)
		h.writeToolsList(w, id, []json.RawMessage{})
		return
	}
	if err != nil {
		h.denyUpstream(w, rec, id, d, err)
		return
	}
	permitted := h.filterTools(ctx, listing.tools, slug, sess)
	rec.Decision, rec.Listed, rec.HiddenByPolicy = "allow", len(permitted), len(listing.tools)-len(permitted)
	h.writeToolsList(w, id, permitted)
}

// newAudit starts a request's audit record. It is a denial until a step
// permits it.
func (h *Handler) newAudit(event, slug string, sess *Session) *AuditRecord {
	rec := &AuditRecord{
		Event: event, DecisionID: uuid.NewString(), Decision: "deny",
		SessionID: sess.SessionID, AgentID: sess.Agent, HarnessKind: sess.HarnessKind, UserID: sess.Subject,
		ConnectorSlug: slug,
	}
	if h.config.Catalog != nil {
		rec.BundleDigest = h.config.Catalog.BundleDigest()
	}
	return rec
}

// emit writes rec. A failed write is logged and never changes the decision
// (ADR-012); the log names no content.
func (h *Handler) emit(ctx context.Context, rec *AuditRecord) {
	if h.config.Auditor == nil {
		return
	}
	if err := h.config.Auditor.Record(ctx, *rec); err != nil {
		h.config.Logger.Warn("mcp_audit_write_failed", "event", rec.Event, "decision_id", rec.DecisionID, "error", err)
	}
}

// deny answers a §4.5 denial and records it under the record's decision id.
func (h *Handler) deny(w http.ResponseWriter, rec *AuditRecord, id any, code int, reason string) {
	rec.Decision, rec.ReasonCode = "deny", reason
	writeDenialID(w, http.StatusOK, id, code, reason, rec.DecisionID)
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
		if _, err := h.config.Authorizer.Authorize(ctx, Decision{
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

// Protocol revisions the route speaks to harnesses (ADR-036 §4.2), latest
// first.
var harnessProtocolVersions = []string{"2026-07-28", "2025-11-25", "2025-06-18"}

// JSON-RPC errors for request metadata headers (ADR-036 §4.2, §4.5 step 2).
const (
	codeHeaderMismatch = -32020
	codeInvalidRequest = -32600
)

// checkRequestHeaders validates the MCP request metadata headers against the
// body. MCP-Protocol-Version, when sent, must be a revision the route speaks;
// Mcp-Method must equal the method; Mcp-Name must equal params.name of a
// tools/call; and on initialize the version header must equal
// params.protocolVersion. An absent header is not checked. It returns a
// JSON-RPC code and message, or 0.
func checkRequestHeaders(header http.Header, req jsonrpcRequest) (int, string) {
	version, hasVersion := headerValue(header, "MCP-Protocol-Version")
	if hasVersion && !speaksProtocolVersion(version) {
		return codeInvalidRequest, "UnsupportedProtocolVersionError"
	}
	if method, ok := headerValue(header, "Mcp-Method"); ok && method != req.Method {
		return codeHeaderMismatch, "HeaderMismatch"
	}
	if name, ok := headerValue(header, "Mcp-Name"); ok && (req.Method != "tools/call" || name != extractTool(req.Params)) {
		return codeHeaderMismatch, "HeaderMismatch"
	}
	if req.Method == "initialize" && hasVersion {
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		if p.ProtocolVersion != "" && p.ProtocolVersion != version {
			return codeHeaderMismatch, "HeaderMismatch"
		}
	}
	return 0, ""
}

// headerValue returns a header's value and whether it was sent at all.
func headerValue(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	if len(values) == 0 {
		return "", false
	}
	return strings.TrimSpace(values[0]), true
}

func speaksProtocolVersion(v string) bool {
	for _, known := range harnessProtocolVersions {
		if v == known {
			return true
		}
	}
	return false
}

// negotiateProtocolVersion answers initialize's protocolVersion: the
// client's requested revision when the route speaks it, else its latest.
func negotiateProtocolVersion(params json.RawMessage) string {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &p)
	for _, v := range harnessProtocolVersions {
		if p.ProtocolVersion == v {
			return v
		}
	}
	return harnessProtocolVersions[0]
}

// extractArguments returns params.arguments, for audit digests only.
func extractArguments(params json.RawMessage) json.RawMessage {
	var p struct {
		Arguments json.RawMessage `json:"arguments"`
	}
	if json.Unmarshal(params, &p) != nil {
		return nil
	}
	return p.Arguments
}
