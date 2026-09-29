// Package gmail is the gmail connector: message.search and message.get
// through the kei-connector-contracts Gmail client. Redaction is the
// client's: search never returns bodies, and message.get returns one only
// when the connector's gmail_include_body policy opts in; otherwise the body
// is never fetched.
package gmail

import (
	"context"

	"github.com/HaikeiLabs/kei-connector-contracts/providers"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/input"
)

// Connector executes gmail reads.
type Connector struct{}

// Execute runs one gmail read.
func (Connector) Execute(ctx context.Context, call connector.Call) (any, error) {
	var payload providers.Payload
	switch in := call.Input.(type) {
	case input.GmailMessageSearch:
		payload = providers.MessageSearchPayload{Query: in.Query, PageSize: in.PageSize, PageToken: in.PageToken}
	case input.GmailMessageGet:
		payload = providers.MessageGetPayload{MessageID: in.MessageID}
	default:
		return nil, connector.ErrInput
	}
	res, err := providers.NewAuthenticatedGmail(call.RuntimeConfig()).Invoke(ctx, call.Meta, call.Invocation, payload)
	if err != nil {
		return nil, err
	}
	return res.Data, nil
}
