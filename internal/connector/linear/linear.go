// Package linear is the linear connector: team.read, project.read,
// cycle.read, and issue.read through the kei-connector-contracts Linear
// GraphQL client. Results are the client's typed structs; issue.read carries
// no description or comments.
package linear

import (
	"context"

	"github.com/HaikeiLabs/kei-connector-contracts/providers"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/input"
)

// Connector executes linear reads.
type Connector struct{}

var payloads = map[string]providers.Payload{
	"team.read":    providers.TeamReadPayload{},
	"project.read": providers.ProjectReadPayload{},
	"cycle.read":   providers.CycleReadPayload{},
	"issue.read":   providers.LinearIssueReadPayload{},
}

// Execute runs one linear read.
func (Connector) Execute(ctx context.Context, call connector.Call) (any, error) {
	payload, ok := payloads[call.Invocation.Capability]
	if _, empty := call.Input.(input.Empty); !ok || !empty {
		return nil, connector.ErrInput
	}
	client := providers.NewLinearRuntime(providers.HTTPLinearGraphQLTransport{Client: call.HTTPClient}, connector.LinearCredential(call.Credential))
	res, err := client.Invoke(ctx, call.Meta, call.Invocation, payload)
	if err != nil {
		return nil, err
	}
	return res.Data, nil
}
