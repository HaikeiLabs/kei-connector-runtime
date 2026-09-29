package httpapi

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/input"
)

// Connector is the http_api connector (D4): one registered base URL per
// connector and its shared-secret key, executed by HTTPExecutor with its SSRF,
// redirect, timeout, size, and redaction rules. The connector's redaction
// rules are its allowlist.
type Connector struct{}

type staticRef string

func (s staticRef) Resolve(context.Context, string) (string, error) { return string(s), nil }

// Execute runs one http.get or http.head.
func (Connector) Execute(ctx context.Context, call connector.Call) (any, error) {
	in, ok := call.Input.(input.HTTPRequest)
	if !ok {
		return nil, connector.ErrInput
	}
	inv := call.Invocation
	inv.HTTP = &contract.HTTPInvocation{Method: contract.HTTPMethod(in.Method), Path: in.Path, Query: in.Query}
	out, err := HTTPExecutor{Credentials: staticRef(call.Credential), Client: call.HTTPClient, LookupIP: call.LookupIP}.ExecuteHTTP(ctx, call.Meta, inv)
	switch {
	case errors.Is(err, errHTTPResponseTooLarge):
		return nil, connector.ErrTooLarge
	case errors.Is(err, errHTTPInvocationDenied):
		return nil, connector.ErrInput
	case err != nil:
		return nil, err
	}
	body := any(string(out.Body))
	if json.Valid(out.Body) {
		body = json.RawMessage(out.Body)
	}
	return map[string]any{"status_code": out.StatusCode, "headers": out.Headers, "body": body}, nil
}
