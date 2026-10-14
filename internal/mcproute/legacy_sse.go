package mcproute

// The deprecated HTTP+SSE transport of MCP 2024-11-05, upstream only
// (ADR-036 §4.2, [MCP-HTTP] "HTTP+SSE Transport (2024-11-05)"). The route
// opens the server's event stream, reads the POST endpoint from its
// "endpoint" event, initializes, sends one request and returns the matching
// response from the stream. The harness side stays Streamable HTTP.

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
)

const (
	transportSSE = "sse"
	// legacyProtocolVersion is the revision HTTP+SSE servers speak.
	legacyProtocolVersion = "2024-11-05"
	legacyInitializeID    = `"kei-initialize"`
)

// legacyExchange sends request (one JSON-RPC request) to an HTTP+SSE server
// with token and the credential_fields headers (either may be empty), on the
// stream GET and every POST, and returns the response message as a JSON
// response, which the caller checks for credential_echo like any other. Every event the stream carries counts toward maxResponseBytes.
// The POST endpoint must have the same scheme and host as mcp.url.
func (h *Handler) legacyExchange(ctx context.Context, d policybundle.Connector, request []byte, token string, headers http.Header) (*http.Response, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // closes the event stream
	stream, err := h.send(ctx, http.MethodGet, d.MCP.URL, nil, token, headers, "text/event-stream")
	if err != nil {
		return nil, err
	}
	defer stream.Body.Close()
	if !isEventStream(stream) {
		return nil, upstreamFailure(reasonUpstreamProtocolError, errors.New("the sse endpoint did not answer with an event stream"))
	}
	events := &sseReader{r: bufio.NewReaderSize(stream.Body, 64<<10), limit: maxResponseBytes}

	endpoint, err := events.endpoint(d.MCP.URL)
	if err != nil {
		return nil, err
	}
	post := func(msg []byte) error {
		resp, err := h.send(ctx, http.MethodPost, endpoint, msg, token, headers, "application/json, text/event-stream")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return nil
	}

	initialize, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": json.RawMessage(legacyInitializeID), "method": "initialize",
		"params": map[string]any{
			"protocolVersion": legacyProtocolVersion, "capabilities": map[string]any{},
			"clientInfo": map[string]any{"name": "kei-connector-runtime", "version": "1.0.0"},
		},
	})
	if err := post(initialize); err != nil {
		return nil, err
	}
	answer, err := events.response(json.RawMessage(legacyInitializeID))
	if err != nil {
		return nil, err
	}
	var init struct {
		Error *json.RawMessage `json:"error"`
	}
	if json.Unmarshal(answer, &init) != nil || init.Error != nil {
		return nil, upstreamFailure(reasonUpstreamProtocolError, errors.New("the sse server refused initialize"))
	}
	if err := post([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)); err != nil {
		return nil, err
	}

	var req struct {
		ID json.RawMessage `json:"id"`
	}
	if json.Unmarshal(request, &req) != nil || len(req.ID) == 0 || string(req.ID) == "null" {
		return nil, upstreamFailure(reasonUpstreamProtocolError, errors.New("only requests are sent over sse"))
	}
	if err := post(request); err != nil {
		return nil, err
	}
	answer, err = events.response(req.ID)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(answer)),
	}, nil
}

// sseReader reads events from an HTTP+SSE stream, counting every byte read
// toward limit.
type sseReader struct {
	r     *bufio.Reader
	limit int
	read  int
}

type sseEvent struct {
	name string
	data []byte
}

// next returns the next complete event.
func (s *sseReader) next() (sseEvent, error) {
	var ev sseEvent
	var data [][]byte
	for {
		line, err := s.r.ReadSlice('\n')
		s.read += len(line)
		if s.read > s.limit {
			return sseEvent{}, upstreamFailure(reasonResponseTooLarge, fmt.Errorf("stream exceeds %d bytes", s.limit))
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			// A line longer than the buffer: keep reading it as data.
			data = append(data, append([]byte(nil), line...))
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return sseEvent{}, upstreamFailure(reasonUpstreamProtocolError, errors.New("the event stream ended"))
			}
			return sseEvent{}, transportError(err)
		}
		line = bytes.TrimRight(line, "\r\n")
		switch {
		case len(line) == 0:
			if ev.name == "" && len(data) == 0 {
				continue
			}
			ev.data = bytes.Join(data, []byte("\n"))
			return ev, nil
		case bytes.HasPrefix(line, []byte("event:")):
			ev.name = strings.TrimSpace(string(line[len("event:"):]))
		case bytes.HasPrefix(line, []byte("data:")):
			data = append(data, append([]byte(nil), bytes.TrimPrefix(line[len("data:"):], []byte(" "))...))
		}
	}
}

// endpoint reads events up to the "endpoint" event and resolves its URL
// against base. The endpoint must not leave base's origin.
func (s *sseReader) endpoint(base string) (string, error) {
	for {
		ev, err := s.next()
		if err != nil {
			return "", err
		}
		if ev.name != "endpoint" {
			continue
		}
		baseURL, err := url.Parse(base)
		if err != nil {
			return "", upstreamFailure(reasonUpstreamBlocked, errors.New("invalid upstream URL"))
		}
		ref, err := url.Parse(strings.TrimSpace(string(ev.data)))
		if err != nil {
			return "", upstreamFailure(reasonUpstreamProtocolError, errors.New("the sse endpoint event is not a URL"))
		}
		u := baseURL.ResolveReference(ref)
		if u.Scheme != baseURL.Scheme || !strings.EqualFold(u.Host, baseURL.Host) || u.User != nil {
			return "", upstreamFailure(reasonUpstreamProtocolError, errors.New("the sse endpoint leaves the server's origin"))
		}
		u.Fragment = ""
		return u.String(), nil
	}
}

// response reads events up to the JSON-RPC response whose id equals id and
// returns it. Notifications and other messages are skipped.
func (s *sseReader) response(id json.RawMessage) ([]byte, error) {
	want := canonicalID(id)
	for {
		ev, err := s.next()
		if err != nil {
			return nil, err
		}
		if ev.name != "" && ev.name != "message" {
			continue
		}
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if json.Unmarshal(ev.data, &msg) != nil || msg.Method != "" || len(msg.ID) == 0 {
			continue
		}
		if canonicalID(msg.ID) == want {
			return ev.data, nil
		}
	}
}

// canonicalID normalizes a JSON-RPC id for comparison.
func canonicalID(id json.RawMessage) string {
	dec := json.NewDecoder(bytes.NewReader(id))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return string(id)
	}
	b, _ := json.Marshal(v)
	return string(b)
}
