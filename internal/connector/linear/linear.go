// Package linear is the linear connector: team.read, project.read,
// cycle.read, and issue.read, plus the issue.create and comment.create writes,
// through the kei-connector-contracts Linear GraphQL client. Results are the
// client's typed structs; issue.read carries no description or comments, and
// a write's result names the new entity without echoing its content.
package linear

import (
	"context"

	"github.com/HaikeiLabs/kei-connector-contracts/providers"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/input"
)

// Connector executes linear reads and writes.
type Connector struct{}

var payloads = map[string]providers.Payload{
	"team.read":    providers.TeamReadPayload{},
	"project.read": providers.ProjectReadPayload{},
	"cycle.read":   providers.CycleReadPayload{},
	"issue.read":   providers.LinearIssueReadPayload{},
}

// Execute runs one linear read or write.
func (Connector) Execute(ctx context.Context, call connector.Call) (any, error) {
	payload, err := payloadFor(call.Invocation.Capability, call.Input)
	if err != nil {
		return nil, err
	}
	client := providers.NewLinearRuntime(providers.HTTPLinearGraphQLTransport{Client: call.HTTPClient}, connector.LinearCredential(call.Credential))
	res, err := client.Invoke(ctx, call.Meta, call.Invocation, payload)
	if err != nil {
		return nil, err
	}
	return res.Data, nil
}

// payloadFor returns the contract payload for a capability and its decoded
// input: the empty read payloads, or the write input itself.
func payloadFor(capability string, in any) (providers.Payload, error) {
	switch typed := in.(type) {
	case input.Empty:
		if payload, ok := payloads[capability]; ok {
			return payload, nil
		}
	case input.LinearIssueCreate:
		if capability == typed.Capability() {
			return typed, nil
		}
	case input.LinearCommentCreate:
		if capability == typed.Capability() {
			return typed, nil
		}
	}
	return nil, connector.ErrInput
}
