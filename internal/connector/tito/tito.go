// Package tito is the tito connector: event.list, event.get, release.list,
// and ticket.summary through the kei-connector-contracts Tito client, using
// the shared-secret API token. Attendee PII never leaves the client: no
// capability lists tickets, and ticket.summary returns counts only.
package tito

import (
	"context"

	"github.com/HaikeiLabs/kei-connector-contracts/providers"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/input"
)

// Connector executes tito reads.
type Connector struct{}

var emptyPayloads = map[string]providers.Payload{
	"event.get":      providers.EventGetPayload{},
	"release.list":   providers.ReleaseListPayload{},
	"ticket.summary": providers.TicketSummaryPayload{},
}

// Execute runs one tito read.
func (Connector) Execute(ctx context.Context, call connector.Call) (any, error) {
	var payload providers.Payload
	switch in := call.Input.(type) {
	case input.TitoEventList:
		payload = providers.EventListPayload{Status: in.Status, Page: in.Page}
	case input.Empty:
		p, ok := emptyPayloads[call.Invocation.Capability]
		if !ok {
			return nil, connector.ErrInput
		}
		payload = p
	default:
		return nil, connector.ErrInput
	}
	res, err := providers.NewAuthenticatedTito(call.RuntimeConfig()).Invoke(ctx, call.Meta, call.Invocation, payload)
	if err != nil {
		return nil, err
	}
	return res.Data, nil
}
