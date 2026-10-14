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

// transportStreamableHTTP is the one upstream transport the route speaks
// today. HTTP+SSE (2024-11-05) upstreams are denied upstream_protocol_error.
const transportStreamableHTTP = "streamable_http"

// callUpstream makes one POST to connector d's mcp.url and returns the
// response. The caller must close resp.Body. Every error is a *routeError
// that never names the upstream URL. A 3xx is never followed (§4.10).
func (h *Handler) callUpstream(ctx context.Context, d policybundle.Connector, sess *Session, body []byte) (*http.Response, error) {
	if d.MCP.Transport != transportStreamableHTTP {
		return nil, upstreamFailure(reasonUpstreamProtocolError, fmt.Errorf("upstream transport %q is not supported", d.MCP.Transport))
	}
	u, err := url.Parse(d.MCP.URL)
	if err != nil {
		return nil, upstreamFailure(reasonUpstreamBlocked, errors.New("invalid upstream URL"))
	}
	if err := h.checkSSRF(u); err != nil {
		return nil, upstreamFailure(reasonUpstreamBlocked, errSSRFBlocked)
	}
	upReq, err := http.NewRequestWithContext(ctx, http.MethodPost, d.MCP.URL, bytes.NewReader(body))
	if err != nil {
		return nil, upstreamFailure(reasonUpstreamBlocked, errors.New("cannot build upstream request"))
	}
	upReq.Header.Set("Content-Type", "application/json")
	upReq.Header.Set("Accept", "application/json, text/event-stream")
	if h.config.TokenSource != nil {
		token, err := h.config.TokenSource.Token(ctx, sess.Subject, d.Slug)
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
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		resp.Body.Close()
		return nil, upstreamFailure(reasonUpstreamProtocolError, fmt.Errorf("upstream status %d", resp.StatusCode))
	}
	return resp, nil
}

// exchange sends one request the route originates (tools/list) and returns
// the JSON-RPC response body, whether the server answered with JSON or an
// SSE stream. The response is capped at maxResponseBytes.
func (h *Handler) exchange(ctx context.Context, d policybundle.Connector, sess *Session, body []byte) ([]byte, error) {
	resp, err := h.callUpstream(ctx, d, sess, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if !isEventStream(resp) {
		return readCapped(resp.Body, maxResponseBytes)
	}
	raw, err := readCapped(resp.Body, maxResponseBytes)
	if err != nil {
		return nil, err
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
func (h *Handler) forwardToUpstream(w http.ResponseWriter, ctx context.Context, id any, d policybundle.Connector, body []byte, sess *Session) {
	resp, err := h.callUpstream(ctx, d, sess, body)
	if err != nil {
		h.denyUpstream(w, id, d, err)
		return
	}
	defer resp.Body.Close()

	if isEventStream(resp) {
		h.relaySSE(w, id, d, resp.Body)
		return
	}

	respBody, err := readCapped(resp.Body, maxResponseBytes)
	if err != nil {
		h.denyUpstream(w, id, d, err)
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
func (h *Handler) relaySSE(w http.ResponseWriter, id any, d policybundle.Connector, body io.Reader) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		h.config.Logger.Error("mcp_sse_flush_unsupported", "slug", d.Slug)
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
			h.endSSE(w, flusher, id, d, upstreamFailure(reasonResponseTooLarge, fmt.Errorf("stream exceeds %d bytes", maxResponseBytes)))
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
				h.endSSE(w, flusher, id, d, transportError(err))
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

// denyUpstream answers a failed upstream exchange with its §4.5 code.
func (h *Handler) denyUpstream(w http.ResponseWriter, id any, d policybundle.Connector, err error) {
	h.logUpstreamFailure(d, err)
	re := upstreamFailure(reasonUpstreamUnreachable, err)
	errors.As(err, &re)
	writeDenial(w, http.StatusOK, id, re.code, re.reason)
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
