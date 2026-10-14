package mcproute

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"

	"github.com/google/uuid"
)

// JSON-RPC error codes of the route (ADR-036 §4.5). They lie outside the
// range JSON-RPC 2.0 reserves, so they never collide with MCP's own codes.
const (
	codeUnauthenticated = -31401
	codeDenied          = -31403
	codeManifest        = -31409
	codeInvalidArgs     = -31400
	codeCredential      = -31424
	codeUpstream        = -31502
)

// Denial reasons (ADR-036 §4.5). They go in error.data.reason.
const (
	errAuthFailed               = "invalid_route_key"
	reasonNonLoopback           = "non_loopback_request"
	reasonConnectorNotFound     = "connector_not_found"
	reasonConnectorNotBound     = "connector_not_bound"
	reasonNoMatchingPolicy      = "no_matching_policy"
	reasonPolicyDenied          = "policy_denied"
	reasonManifestUnapproved    = "mcp_manifest_unapproved"
	reasonManifestDrift         = "mcp_manifest_drift"
	reasonToolNotApproved       = "mcp_tool_not_approved"
	reasonCredentialUnavailable = "credential_unavailable"
	// reasonCredentialAudienceMismatch: the released token is for another
	// connector or resource (HAI-577 AUDIENCE_MISMATCH, or a wrong echo).
	reasonCredentialAudienceMismatch = "credential_audience_mismatch"
	reasonCredentialRejected         = "credential_rejected"
	reasonInsufficientScope          = "insufficient_scope"
	reasonUpstreamBlocked            = "upstream_blocked"
	reasonUpstreamUnreachable        = "upstream_unreachable"
	reasonUpstreamTimeout            = "upstream_timeout"
	reasonUpstreamProtocolError      = "upstream_protocol_error"
	reasonResponseTooLarge           = "response_too_large"
	// reasonCredentialEcho: the upstream response contained the credential.
	reasonCredentialEcho = "credential_echo"
)

// routeError is a failure that ends a request with one §4.5 code and reason.
// err is diagnostic detail for the log only; it never names an upstream URL.
type routeError struct {
	code   int
	reason string
	err    error
	// scope is the challenged scope of an insufficient_scope answer.
	scope string
}

func (e *routeError) Error() string {
	if e.err == nil {
		return e.reason
	}
	return e.reason + ": " + e.err.Error()
}

func (e *routeError) Unwrap() error { return e.err }

func upstreamFailure(reason string, err error) *routeError {
	return &routeError{code: codeUpstream, reason: reason, err: err}
}

// transportError classifies an upstream transport failure and drops the
// request URL from it: a *url.Error names the full URL, which can carry a
// secret path or query and must never reach a log.
func transportError(err error) *routeError {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	var ne net.Error
	switch {
	case errors.Is(err, errSSRFBlocked):
		return upstreamFailure(reasonUpstreamBlocked, err)
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return upstreamFailure(reasonUpstreamTimeout, err)
	default:
		return upstreamFailure(reasonUpstreamUnreachable, err)
	}
}

type rpcErrorData struct {
	Reason     string `json:"reason"`
	DecisionID string `json:"decision_id"`
}

// writeDenial writes a §4.5 error: error.data is the reason and a fresh
// decision id, and nothing else.
func writeDenial(w http.ResponseWriter, status int, id any, code int, reason string) {
	writeDenialID(w, status, id, code, reason, uuid.NewString())
}

// writeDenialID is writeDenial with the decision id of the request's audit
// record.
func writeDenialID(w http.ResponseWriter, status int, id any, code int, reason, decisionID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(jsonrpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &jsonrpcError{
			Code:    code,
			Message: reason,
			Data:    &rpcErrorData{Reason: reason, DecisionID: decisionID},
		},
	})
}
