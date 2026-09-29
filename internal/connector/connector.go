// Package connector is the seam between the invoke flow and the
// per-provider connector packages (internal/connector/<name>). The invoke
// flow decides, resolves the credential, and hands each connector one Call;
// the connector wraps the kei-connector-contracts provider client, applies
// its redaction, and returns only allow-listed data.
package connector

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-contracts/providers"
)

// Call is one allowed read, ready to execute.
type Call struct {
	Meta       contract.Metadata
	Invocation contract.Invocation
	// Input is the typed value from input.Decode for this capability.
	Input any
	// Credential is the resolved secret or OAuth access token. It is used for
	// this call only and must never be logged or returned.
	Credential string
	// HTTPClient caps response sizes and records provider status; connectors
	// must send every provider request through it.
	HTTPClient *http.Client
	LookupIP   func(context.Context, string) ([]net.IP, error)
	Now        func() time.Time
}

// Connector executes one provider's read capabilities.
type Connector interface {
	Execute(ctx context.Context, call Call) (any, error)
}

var (
	// ErrConfig means the connector's descriptor lacks what execution needs
	// (reason code descriptor_invalid).
	ErrConfig = errors.New("connector config is incomplete")
	// ErrInput means the input does not fit the capability (input_invalid).
	ErrInput = errors.New("input does not fit the capability")
	// ErrTooLarge means a result exceeds its limit (result_too_large).
	ErrTooLarge = errors.New("result exceeds the size limit")
)

// Credential adapts a resolved credential to the provider clients' resolver
// seams. It returns the same value for every scope: the invoke flow already
// bound it to this invocation.
type Credential string

func (c Credential) Resolve(context.Context, string, string, string, string) (string, error) {
	return string(c), nil
}

// LinearCredential adapts a resolved credential to the Linear client's seam.
type LinearCredential string

func (c LinearCredential) Resolve(context.Context, string, providers.LinearCredentialScope) (string, error) {
	return string(c), nil
}

// RuntimeConfig is the provider-client configuration for a call.
func (c Call) RuntimeConfig() providers.RuntimeConfig {
	return providers.RuntimeConfig{HTTPClient: c.HTTPClient, Credentials: Credential(c.Credential)}
}
