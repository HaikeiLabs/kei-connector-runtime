package mcproute

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

// echoGuard holds a copy of the credential released for one upstream
// exchange, for as long as that exchange's response is read, so the route
// can drop a response that echoes it (ADR-036 §4.9 credential_echo). The
// copy is zeroed by wipe. A nil guard (no credential sent) finds nothing.
type echoGuard struct {
	secret []byte
}

func newEchoGuard(token string) *echoGuard {
	if token == "" {
		return nil
	}
	return &echoGuard{secret: []byte(token)}
}

// wipe zeroes the held copy.
func (g *echoGuard) wipe() {
	if g == nil {
		return
	}
	for i := range g.secret {
		g.secret[i] = 0
	}
	g.secret = nil
}

var errCredentialEcho = errors.New("the upstream response contains the credential")

func credentialEcho() *routeError {
	return upstreamFailure(reasonCredentialEcho, errCredentialEcho)
}

// leaks reports whether b carries the credential: in its raw bytes, or in
// any JSON string it holds once JSON escapes (\/, \uXXXX, ...) are decoded.
// b is a JSON document or an SSE event whose data lines are JSON.
func (g *echoGuard) leaks(b []byte) bool {
	if g == nil || len(g.secret) == 0 {
		return false
	}
	if bytes.Contains(b, g.secret) {
		return true
	}
	if g.jsonLeaks(b) {
		return true
	}
	var data []byte
	for _, line := range bytes.Split(b, []byte("\n")) {
		if rest, ok := bytes.CutPrefix(bytes.TrimRight(line, "\r"), []byte("data:")); ok {
			data = append(data, bytes.TrimPrefix(rest, []byte(" "))...)
			data = append(data, '\n')
		}
	}
	return len(data) > 0 && g.jsonLeaks(data)
}

func (g *echoGuard) jsonLeaks(b []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	for {
		var v any
		if err := dec.Decode(&v); err != nil {
			return false
		}
		if g.valueLeaks(v) {
			return true
		}
	}
}

func (g *echoGuard) valueLeaks(v any) bool {
	switch x := v.(type) {
	case string:
		return strings.Contains(x, string(g.secret))
	case []any:
		for _, e := range x {
			if g.valueLeaks(e) {
				return true
			}
		}
	case map[string]any:
		for k, e := range x {
			if strings.Contains(k, string(g.secret)) || g.valueLeaks(e) {
				return true
			}
		}
	}
	return false
}
