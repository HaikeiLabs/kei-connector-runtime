package connectorruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"time"
)

const (
	maxToolAuthorizeRequest = 64 << 10
	maxToolNameLen          = 128
)

// toolNamePattern mirrors the catalog's validation of the authorize "tool"
// field (HAI-271).
var toolNamePattern = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)*$`)

func validateToolName(tool string) error {
	if tool == "" {
		return fmt.Errorf("tool is required")
	}
	if len(tool) > maxToolNameLen {
		return fmt.Errorf("tool must be at most %d characters", maxToolNameLen)
	}
	if !toolNamePattern.MatchString(tool) {
		return fmt.Errorf("tool must match %s", toolNamePattern)
	}
	return nil
}

// unixConnKey marks request contexts that arrived on the runtime Unix socket.
type unixConnKey struct{}

// markUnixConn is the http.Server ConnContext hook. The socket is owner-only
// (0600), so file permissions are its authentication; the TCP listener has no
// equivalent and never serves socket-only routes.
func markUnixConn(ctx context.Context, c net.Conn) context.Context {
	if c.LocalAddr().Network() == "unix" {
		return context.WithValue(ctx, unixConnKey{}, true)
	}
	return ctx
}

func fromUnixSocket(r *http.Request) bool {
	v, _ := r.Context().Value(unixConnKey{}).(bool)
	return v
}

// toolAuthorizeRequest is the POST /v1/authorize body. Resource and Resources
// exist only to reject callers that still send them: with a tool, the catalog
// decides against the workspace tool registry scope (HAI-271).
type toolAuthorizeRequest struct {
	Tool            string `json:"tool"`
	Action          string `json:"action"`
	InvokingSubject string `json:"invoking_subject"`
	SpanID          string `json:"span_id"`
	ParentSpan      string `json:"parent_span"`
	DelegationDepth int    `json:"delegation_depth"`
	AgentVersion    string `json:"agent_version"`
	Framework       string `json:"framework"`
	ToolArgsDigest  string `json:"tool_args_digest"`

	Resource  json.RawMessage `json:"resource"`
	Resources json.RawMessage `json:"resources"`
}

// toolAuthorizeResponse mirrors AuthorizeOutput without the credential: secret
// material never crosses the socket.
type toolAuthorizeResponse struct {
	Decision   string           `json:"decision"`
	Reason     string           `json:"reason,omitempty"`
	Code       string           `json:"code,omitempty"`
	Service    string           `json:"service,omitempty"`
	Enrollment *json.RawMessage `json:"enrollment,omitempty"`
	Connect    *json.RawMessage `json:"connect,omitempty"`
}

// handleToolAuthorize decides a tool call with the daemon's own runtime
// credential. Only "allow" returns 200; every other outcome is a deny for the
// caller.
func (h *runtimeHTTPHandler) handleToolAuthorize(w http.ResponseWriter, r *http.Request) {
	if err := h.runtimeConfigError(); err != nil {
		writeToolDeny(w, http.StatusServiceUnavailable, "runtime_not_configured", err.Error())
		return
	}

	var req toolAuthorizeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxToolAuthorizeRequest)).Decode(&req); err != nil {
		writeToolDeny(w, http.StatusBadRequest, "invalid_request", "request body must be a JSON object")
		return
	}
	if err := validateToolName(req.Tool); err != nil {
		writeToolDeny(w, http.StatusBadRequest, "invalid_tool", err.Error())
		return
	}
	if req.Resource != nil || req.Resources != nil {
		writeToolDeny(w, http.StatusBadRequest, "resource_not_allowed", "resource scope comes from the workspace tool registry; send tool and optional action only")
		return
	}
	if req.InvokingSubject != "" {
		if err := validateInvokingSubject(req.InvokingSubject); err != nil {
			writeToolDeny(w, http.StatusBadRequest, "invalid_invoking_subject", "invoking_subject is malformed")
			return
		}
	}
	if req.DelegationDepth < 0 {
		writeToolDeny(w, http.StatusBadRequest, "invalid_request", "delegation_depth must not be negative")
		return
	}

	registry, err := LoadRegistry(h.cfg.RegistryPath)
	if err != nil {
		slog.Warn("tool_authorize_registry_unavailable", "error", err)
		writeToolDeny(w, http.StatusServiceUnavailable, "registry_unavailable", "tool registry is unavailable")
		return
	}
	if h.credentialBinding != nil && h.secretStore == nil {
		writeToolDeny(w, http.StatusServiceUnavailable, "secret_store_unavailable", "runtime secret store is unavailable")
		return
	}

	providerUser := h.cfg.ProviderUserID
	if providerUser == "" {
		providerUser = req.InvokingSubject
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	service := registry.Service(req.Tool)
	out, err := decideTool(authorizeParams{
		ctx:               ctx,
		user:              req.InvokingSubject,
		providerUser:      providerUser,
		tool:              req.Tool,
		catalogTool:       req.Tool,
		action:            req.Action,
		harness:           h.cfg.RuntimeToken,
		abac:              h.abac,
		credentialBinding: h.credentialBinding,
		secretStore:       h.secretStore,
		oidcBridge:        h.oidcBridge,
		auditPath:         h.cfg.AuditPath,
		auditMaxBytes:     h.cfg.AuditMaxBytes,
		registry:          registry,
		spanID:            req.SpanID,
		invokingSubject:   req.InvokingSubject,
		parentSpan:        req.ParentSpan,
		delegationDepth:   req.DelegationDepth,
		agentID:           envOr("KEI_PROXY_AGENT_ID", ""),
		agentVersion:      firstNonEmpty(req.AgentVersion, envOr("KEI_PROXY_AGENT_VERSION", "")),
		framework:         firstNonEmpty(req.Framework, envOr("KEI_PROXY_FRAMEWORK", "")),
		toolArgsDigest:    req.ToolArgsDigest,
	}, service, "")
	if err != nil {
		slog.Warn("tool_authorize_unavailable", "tool", req.Tool, "error", err)
		writeToolDeny(w, http.StatusServiceUnavailable, "authorization_unavailable", "authorization unavailable (fail closed)")
		return
	}

	status := http.StatusForbidden
	if out.Decision == "allow" {
		status = http.StatusOK
	}
	writeToolAuthorize(w, status, toolAuthorizeResponse{
		Decision:   out.Decision,
		Reason:     out.Reason,
		Service:    out.Service,
		Enrollment: out.Enrollment,
		Connect:    out.Connect,
	})
}

func writeToolDeny(w http.ResponseWriter, status int, code, reason string) {
	writeToolAuthorize(w, status, toolAuthorizeResponse{Decision: "deny", Reason: reason, Code: code})
}

func writeToolAuthorize(w http.ResponseWriter, status int, body toolAuthorizeResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
