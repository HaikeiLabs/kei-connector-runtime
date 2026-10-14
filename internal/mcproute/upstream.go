package mcproute

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
	"github.com/google/uuid"
)

// transportStreamableHTTP is the Streamable HTTP upstream transport; the
// other one is transportSSE (HTTP+SSE, legacy_sse.go).
const transportStreamableHTTP = "streamable_http"

// Auth methods of an mcp descriptor (ADR-036 §3.3).
const (
	authMethodNone      = "none"
	authMethodSecretRef = "secret_ref"
)

// callUpstream makes one POST to connector d's mcp.url and returns the
// response with a guard holding the credential sent (nil when none), to check
// the response for credential_echo. The caller must close resp.Body and wipe
// the guard. Every error is a *routeError that never names the upstream URL
// or carries the credential. A 3xx is never followed (§4.10).
func (h *Handler) callUpstream(ctx context.Context, d policybundle.Connector, sess *Session, body []byte) (*http.Response, *echoGuard, error) {
	resp, sent, err := h.sendUpstream(ctx, d, sess, body)
	if err != nil {
		return nil, nil, err
	}
	return resp, newEchoGuard(sent...), nil
}

// sendUpstream is callUpstream returning the credentials it attached.
func (h *Handler) sendUpstream(ctx context.Context, d policybundle.Connector, sess *Session, body []byte) (*http.Response, []string, error) {
	if d.MCP.Transport != transportStreamableHTTP && d.MCP.Transport != transportSSE {
		return nil, nil, upstreamFailure(reasonUpstreamProtocolError, fmt.Errorf("upstream transport %q is not supported", d.MCP.Transport))
	}
	u, err := url.Parse(d.MCP.URL)
	if err != nil {
		return nil, nil, upstreamFailure(reasonUpstreamBlocked, errors.New("invalid upstream URL"))
	}
	if err := h.checkSSRF(u); err != nil {
		return nil, nil, upstreamFailure(reasonUpstreamBlocked, errSSRFBlocked)
	}
	// exchange is one request over the connector's transport, with the
	// Bearer token or credential_fields headers (either may be empty).
	exchange := func(token string, headers http.Header) (*http.Response, error) {
		if d.MCP.Transport == transportSSE {
			return h.legacyExchange(ctx, d, body, token, headers)
		}
		return h.send(ctx, http.MethodPost, d.MCP.URL, body, token, headers, "application/json, text/event-stream")
	}
	switch d.MCP.AuthMethod {
	case authMethodNone:
		resp, err := exchange("", nil)
		return resp, nil, err
	case authMethodSecretRef:
		// §4.8: the credential_fields headers, from the tenant secret store.
		headers, values, err := h.secretHeaders(ctx, d)
		if err != nil {
			return nil, nil, credentialDenial(reasonCredentialUnavailable, err)
		}
		resp, err := exchange("", headers)
		return resp, values, err
	}
	// Step 10 (§4.8): the session's credential for this connector, released
	// for exactly its canonical resource.
	if h.config.Credentials == nil {
		return nil, nil, credentialDenial(reasonCredentialUnavailable, errors.New("no credential source"))
	}
	var resp *http.Response
	var sent string
	err = h.config.Credentials.UseCredential(ctx, sess, d.ID, d.MCP.URL, func(c ConnectorCredential) error {
		if c.ConnectorID != d.ID || c.Resource != d.MCP.URL {
			return credentialDenial(reasonCredentialAudienceMismatch, errors.New("the credential was released for another connector or resource"))
		}
		r, err := exchange(c.AccessToken, nil)
		// A copy outlives the callback only for this response's echo check.
		resp, sent = r, strings.Clone(c.AccessToken)
		return err
	})
	var re *routeError
	if errors.As(err, &re) {
		if re.reason == reasonCredentialRejected {
			h.config.Credentials.Discard(sess, d.ID, d.MCP.URL)
		}
		return nil, nil, re
	}
	if err != nil {
		var denied *CredentialDenied
		if errors.As(err, &denied) && denied.Reason == "AUDIENCE_MISMATCH" {
			return nil, nil, credentialDenial(reasonCredentialAudienceMismatch, err)
		}
		return nil, nil, credentialDenial(reasonCredentialUnavailable, err)
	}
	return resp, []string{sent}, nil
}

func credentialDenial(reason string, err error) *routeError {
	return &routeError{code: codeCredential, reason: reason, err: err}
}

// send makes one upstream request (a POST of body, or the GET of an sse
// stream when body is nil) with token and the credential_fields headers
// (either may be empty) and maps the HTTP status: 3xx and other non-2xx are
// upstream_protocol_error, 401 is credential_rejected, and 403
// insufficient_scope carries the challenged scope (§4.8). The route retries
// nothing.
func (h *Handler) send(ctx context.Context, method, target string, body []byte, token string, headers http.Header, accept string) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	upReq, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, upstreamFailure(reasonUpstreamBlocked, errors.New("cannot build upstream request"))
	}
	if body != nil {
		upReq.Header.Set("Content-Type", "application/json")
	}
	upReq.Header.Set("Accept", accept)
	if token != "" {
		upReq.Header.Set("Authorization", "Bearer "+token)
	}
	for name, values := range headers {
		upReq.Header[name] = values
	}
	resp, err := h.client.Do(upReq)
	if err != nil {
		return nil, transportError(err)
	}
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		resp.Body.Close()
		return nil, upstreamFailure(reasonUpstreamProtocolError, fmt.Errorf("upstream redirect %d not followed", resp.StatusCode))
	case resp.StatusCode == http.StatusUnauthorized && token != "":
		resp.Body.Close()
		return nil, credentialDenial(reasonCredentialRejected, errors.New("upstream rejected the credential"))
	case resp.StatusCode == http.StatusForbidden && token != "":
		if scope, ok := insufficientScope(resp.Header.Values("WWW-Authenticate")); ok {
			resp.Body.Close()
			re := credentialDenial(reasonInsufficientScope, errors.New("upstream requires more scope"))
			re.scope = scope
			return nil, re
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		resp.Body.Close()
		return nil, upstreamFailure(reasonUpstreamProtocolError, fmt.Errorf("upstream status %d", resp.StatusCode))
	}
	return resp, nil
}

// insufficientScope reads an RFC 6750 Bearer challenge with
// error="insufficient_scope" and returns its scope parameter.
func insufficientScope(challenges []string) (string, bool) {
	for _, ch := range challenges {
		params, ok := bearerChallengeParams(ch)
		if ok && params["error"] == "insufficient_scope" {
			return params["scope"], true
		}
	}
	return "", false
}

// bearerChallengeParams parses `Bearer k="v", k2=v2` into its parameters.
func bearerChallengeParams(ch string) (map[string]string, bool) {
	scheme, rest, _ := strings.Cut(strings.TrimSpace(ch), " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return nil, false
	}
	params := map[string]string{}
	for rest = strings.TrimSpace(rest); rest != ""; {
		key, after, ok := strings.Cut(rest, "=")
		if !ok {
			break
		}
		key, after = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(after)
		var value string
		if strings.HasPrefix(after, `"`) {
			end := strings.Index(after[1:], `"`)
			if end < 0 {
				break
			}
			value, after = after[1:end+1], after[end+2:]
		} else {
			value, after, _ = strings.Cut(after, ",")
			value = strings.TrimSpace(value)
			after = "," + after
		}
		params[key] = value
		rest = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(after), ","))
	}
	return params, true
}

// exchange sends one request the route originates (tools/list) and returns
// the JSON-RPC response body, whether the server answered with JSON or an
// SSE stream. The response is capped at maxResponseBytes.
func (h *Handler) exchange(ctx context.Context, d policybundle.Connector, sess *Session, body []byte) ([]byte, error) {
	resp, guard, err := h.callUpstream(ctx, d, sess, body)
	if err != nil {
		return nil, err
	}
	defer guard.wipe()
	defer resp.Body.Close()
	raw, err := readCapped(resp.Body, maxResponseBytes)
	if err != nil {
		return nil, err
	}
	if guard.leaks(raw) {
		return nil, credentialEcho()
	}
	if !isEventStream(resp) {
		return raw, nil
	}
	// The response is the first event whose data is a JSON-RPC response (it
	// has an id); notifications before it are skipped.
	for _, event := range bytes.Split(bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n")), []byte("\n\n")) {
		var data []byte
		for _, line := range bytes.Split(event, []byte("\n")) {
			if rest, ok := bytes.CutPrefix(line, []byte("data:")); ok {
				data = append(data, bytes.TrimPrefix(rest, []byte(" "))...)
			}
		}
		var msg struct {
			ID json.RawMessage `json:"id"`
		}
		if len(data) > 0 && json.Unmarshal(data, &msg) == nil && len(msg.ID) > 0 && string(msg.ID) != "null" {
			return data, nil
		}
	}
	return nil, upstreamFailure(reasonUpstreamProtocolError, errors.New("event stream ended without a response"))
}

func isEventStream(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream")
}

// forwardToUpstream sends one tools/call and relays the response. Only the
// route's own Content-Type is set: no upstream header reaches the harness.
func (h *Handler) forwardToUpstream(w http.ResponseWriter, ctx context.Context, rec *AuditRecord, id any, d policybundle.Connector, body []byte, sess *Session) {
	start := h.now()
	rec.Forwarded, rec.UpstreamHost = true, upstreamHost(d.MCP.URL)
	defer func() { rec.DurationMS = h.now().Sub(start).Milliseconds() }()
	resp, guard, err := h.callUpstream(ctx, d, sess, body)
	if err != nil {
		h.denyUpstream(w, rec, id, d, err)
		return
	}
	defer guard.wipe()
	defer resp.Body.Close()
	rec.UpstreamStatus = resp.StatusCode

	if isEventStream(resp) {
		rec.ResponseBytes = h.relaySSE(w, rec, id, d, resp.Body, guard)
		return
	}

	respBody, err := readCapped(resp.Body, maxResponseBytes)
	if err != nil {
		h.denyUpstream(w, rec, id, d, err)
		return
	}
	if guard.leaks(respBody) {
		h.denyUpstream(w, rec, id, d, credentialEcho())
		return
	}
	rec.ResponseBytes = len(respBody)
	rec.IsError, rec.JSONRPCErrorCode = resultOutcome(respBody)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respBody)
}

// resultOutcome reads, for audit only, whether a tools/call response is a
// tool error (result.isError) or a JSON-RPC error and its code.
func resultOutcome(body []byte) (isError bool, code int) {
	var msg struct {
		Result *struct {
			IsError bool `json:"isError"`
		} `json:"result"`
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &msg) != nil {
		return false, 0
	}
	if msg.Error != nil {
		return true, msg.Error.Code
	}
	return msg.Result != nil && msg.Result.IsError, 0
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
// response_too_large error for the request instead (ADR-036 §4.9). It
// returns the number of bytes relayed.
func (h *Handler) relaySSE(w http.ResponseWriter, rec *AuditRecord, id any, d policybundle.Connector, body io.Reader, guard *echoGuard) int {
	flusher, ok := w.(http.Flusher)
	if !ok {
		h.config.Logger.Error("mcp_sse_flush_unsupported", "slug", d.Slug)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return 0
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
			h.endSSE(w, flusher, id, d, upstreamFailure(reasonResponseTooLarge, fmt.Errorf("stream exceeds %d bytes", maxResponseBytes)))
			return total
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			if guard.leaks(event.Bytes()) {
				h.echoed(w, flusher, rec, id, d)
				return total
			}
			if event.Len() > 0 {
				w.Write(event.Bytes())
				flusher.Flush()
				total += event.Len()
			}
			if !errors.Is(err, io.EOF) {
				h.endSSE(w, flusher, id, d, transportError(err))
			}
			return total
		}
		if line := bytes.TrimRight(chunk, "\r\n"); len(line) == 0 {
			if guard.leaks(event.Bytes()) {
				h.echoed(w, flusher, rec, id, d)
				return total
			}
			w.Write(event.Bytes())
			flusher.Flush()
			total += event.Len()
			event.Reset()
		}
	}
}

// echoed ends a relayed stream at an event that carries the credential: the
// event is dropped, and the call is denied credential_echo.
func (h *Handler) echoed(w io.Writer, flusher http.Flusher, rec *AuditRecord, id any, d policybundle.Connector) {
	rec.Decision, rec.ReasonCode = "deny", reasonCredentialEcho
	h.endSSE(w, flusher, id, d, credentialEcho())
}

// endSSE terminates a relayed stream with a JSON-RPC error event.
func (h *Handler) endSSE(w io.Writer, flusher http.Flusher, id any, d policybundle.Connector, re *routeError) {
	h.logUpstreamFailure(d, re)
	msg, _ := json.Marshal(jsonrpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &jsonrpcError{Code: re.code, Message: re.reason, Data: &rpcErrorData{Reason: re.reason, DecisionID: uuid.NewString()}},
	})
	fmt.Fprintf(w, "event: message\ndata: %s\n\n", msg)
	flusher.Flush()
}

// denyUpstream answers a failed upstream exchange (or manifest step) with
// its §4.5 code and records it.
func (h *Handler) denyUpstream(w http.ResponseWriter, rec *AuditRecord, id any, d policybundle.Connector, err error) {
	h.logUpstreamFailure(d, err)
	re := upstreamFailure(reasonUpstreamUnreachable, err)
	errors.As(err, &re)
	rec.ChallengedScope = re.scope
	h.deny(w, rec, id, re.code, re.reason)
}

// logUpstreamFailure logs the connector slug and upstream host, never the
// URL: its path or query can hold a secret.
func (h *Handler) logUpstreamFailure(d policybundle.Connector, err error) {
	h.config.Logger.Warn("mcp_upstream_failed", "slug", d.Slug, "upstream_host", upstreamHost(d.MCP.URL), "error", err)
}

func upstreamHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}
