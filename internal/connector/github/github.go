// Package github is the github connector: repository, issue, pull request,
// check, and workflow reads through the kei-connector-contracts GitHub
// client. Results are the client's typed structs.
package github

import (
	"context"

	"github.com/HaikeiLabs/kei-connector-contracts/providers"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/input"
)

// Connector executes github reads.
type Connector struct{}

var payloads = map[string]providers.Payload{
	"repository.read":   providers.RepositoryReadPayload{},
	"issue.read":        providers.GitHubIssueReadPayload{},
	"pull_request.read": providers.PullRequestReadPayload{},
	"check.read":        providers.CheckReadPayload{},
	"workflow.read":     providers.WorkflowReadPayload{},
}

// Execute runs one github read.
func (Connector) Execute(ctx context.Context, call connector.Call) (any, error) {
	payload, ok := payloads[call.Invocation.Capability]
	if _, empty := call.Input.(input.Empty); !ok || !empty {
		return nil, connector.ErrInput
	}
	res, err := providers.NewAuthenticatedGitHub(call.RuntimeConfig()).Invoke(ctx, call.Meta, call.Invocation, payload)
	if err != nil {
		return nil, err
	}
	return res.Data, nil
}
