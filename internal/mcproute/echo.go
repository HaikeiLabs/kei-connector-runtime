package mcproute

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

// echoGuard holds copies of the credentials sent on one upstream exchange,
// for as long as that exchange's response is read, so the route can drop a
// response that echoes any of them (ADR-036 §4.9 credential_echo). The copies
// are zeroed by wipe. A nil guard (no credential sent) finds nothing.
type echoGuard struct {
	secrets [][]byte
}

func newEchoGuard(values ...string) *echoGuard {
	var secrets [][]byte
	for _, v := range values {
		if v != "" {
			secrets = append(secrets, []byte(v))
		}
	}
	if len(secrets) == 0 {
		return nil
	}
	return &echoGuard{secrets: secrets}
}

// wipe zeroes the held copies.
func (g *echoGuard) wipe() {
	if g == nil {
		return
	}
	for _, s := range g.secrets {
		for i := range s {
			s[i] = 0
		}
	}
	g.secrets = nil
}

var errCredentialEcho = errors.New("the upstream response contains the credential")

func credentialEcho() *routeError {
	return upstreamFailure(reasonCredentialEcho, errCredentialEcho)
}

// leaks reports whether b carries any held credential: in its raw bytes, or
// in any JSON string it holds once JSON escapes (\/, \uXXXX, ...) are
// decoded. b is a JSON document or an SSE event whose data lines are JSON.
func (g *echoGuard) leaks(b []byte) bool {
	if g == nil {
		return false
	}
	var data []byte
	for _, line := range bytes.Split(b, []byte("\n")) {
		if rest, ok := bytes.CutPrefix(bytes.TrimRight(line, "\r"), []byte("data:")); ok {
			data = append(data, bytes.TrimPrefix(rest, []byte(" "))...)
			data = append(data, '\n')
		}
	}
	for _, secret := range g.secrets {
		if len(secret) == 0 {
			continue
		}
		if bytes.Contains(b, secret) || jsonLeaks(b, string(secret)) || (len(data) > 0 && jsonLeaks(data, string(secret))) {
			return true
		}
	}
	return false
}

func jsonLeaks(b []byte, secret string) bool {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	for {
		var v any
		if err := dec.Decode(&v); err != nil {
			return false
		}
		if valueLeaks(v, secret) {
			return true
		}
	}
}

func valueLeaks(v any, secret string) bool {
	switch x := v.(type) {
	case string:
		return strings.Contains(x, secret)
	case []any:
		for _, e := range x {
			if valueLeaks(e, secret) {
				return true
			}
		}
	case map[string]any:
		for k, e := range x {
			if strings.Contains(k, secret) || valueLeaks(e, secret) {
				return true
			}
		}
	}
	return false
}
