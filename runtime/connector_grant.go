package runtime

import (
	"context"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/invoke"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
)

// ConnectorGrant adapts the local PDP's connector decision to the serve
// daemon's POST /v1/connectors:invoke and POST /v1/commands:run routes. A v2
// tool call resolves its registered connector; a legacy call is decided by
// the PDP. Either way the grant carries the connector's bundle descriptor
// (HAI-378) from the same bundle the decision used.
func (l *LocalPDP) ConnectorGrant(ctx context.Context, c invoke.DaemonCall) (invoke.Grant, error) {
	if c.ToolName != "" {
		subjectSnapshot, hasSession := l.Sessions.Get(c.Session)
		if !hasSession {
			return invoke.Grant{ReasonCode: pdp.ReasonSessionNotFound}, nil
		}
		target, ok := l.DescribeV2Tool(c.Session, c.ToolName, c.AgentID)
		if target.Subject != subjectSnapshot.UserID {
			ok = false
		}
		return invoke.Grant{
			V2Tool: ok, HasSession: true, Subject: target.Subject, AgentID: target.AgentID,
			Provider: target.Provider, ConnectorID: target.ConnectorID, Capabilities: target.Capabilities,
			TenantID: target.TenantID, WorkspaceID: target.WorkspaceID,
			Connector: target.Connector, Descriptors: target.Descriptors,
		}, nil
	}
	g, id, err := l.AuthorizeConnector(ctx, pdp.Request{
		Session:  c.Session,
		Resource: c.Resource, AgentID: c.AgentID,
		Connector: &pdp.ConnectorTarget{ConnectorID: c.ConnectorID, Capability: c.Capability},
	})
	if err != nil {
		return invoke.Grant{}, err
	}
	out := invoke.Grant{Allow: g.Allow, ReasonCode: g.ReasonCode, Reason: g.Reason, Enrollment: g.Enrollment, HasSession: g.HasSession, Descriptors: g.Descriptors}
	if g.HasSession && g.Subject.Status == pdp.StatusLinked {
		out.Subject = g.Subject.UserID
	}
	if g.Connector != nil {
		out.Provider = g.Connector.Provider
		out.ConnectorID = g.Connector.ID
		for _, capability := range g.Connector.Capabilities {
			out.Capabilities = append(out.Capabilities, capability.Name)
		}
		if g.Descriptors {
			out.Connector = g.Connector
		}
	}
	if id != nil && id.WorkspaceID != nil {
		out.TenantID, out.WorkspaceID = id.OrgID, *id.WorkspaceID
	}
	return out, nil
}
