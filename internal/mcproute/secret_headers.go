package mcproute

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

// deniedCredentialHeaders are header names a credential_fields entry may not
// use (contract "mcp.credential_fields exact schema"): headers that carry
// other meaning, and the ones the route sets itself. Compared lowercased.
var deniedCredentialHeaders = map[string]bool{
	"authorization":        true,
	"host":                 true,
	"content-length":       true,
	"cookie":               true,
	"mcp-session-id":       true,
	"mcp-protocol-version": true,
	"content-type":         true,
	"accept":               true,
}

// secretHeaders resolves a secret_ref connector's credential_fields into the
// headers to send and the secret values (for credential_echo). Every field
// must resolve. Fields must be unique, headers unique case-insensitively and
// not denied, and a value must not hold a line break. Errors name no value.
func (h *Handler) secretHeaders(ctx context.Context, d policybundle.Connector) (http.Header, []string, error) {
	fields := d.MCP.CredentialFields
	if len(fields) == 0 {
		return nil, nil, errors.New("the secret_ref descriptor has no credential_fields")
	}
	if h.config.Secrets == nil {
		return nil, nil, errors.New("no secret source")
	}
	headers := http.Header{}
	values := make([]string, 0, len(fields))
	seenField, seenHeader := map[string]bool{}, map[string]bool{}
	for _, f := range fields {
		name := strings.ToLower(f.Header)
		switch {
		case seenField[f.Field]:
			return nil, nil, fmt.Errorf("credential field %q is listed twice", f.Field)
		case seenHeader[name]:
			return nil, nil, fmt.Errorf("credential header %q is listed twice", f.Header)
		case deniedCredentialHeaders[name]:
			return nil, nil, fmt.Errorf("credential header %q is not allowed", f.Header)
		}
		seenField[f.Field], seenHeader[name] = true, true
		value, err := h.config.Secrets.Resolve(ctx, d, f.Field)
		if err != nil || value == "" {
			return nil, nil, fmt.Errorf("credential field %q is not available", f.Field)
		}
		if strings.ContainsAny(value, "\r\n\x00") || strings.ContainsAny(f.Prefix, "\r\n\x00") {
			return nil, nil, fmt.Errorf("credential field %q is not a valid header value", f.Field)
		}
		headers.Set(f.Header, f.Prefix+value)
		values = append(values, value)
	}
	return headers, values, nil
}
