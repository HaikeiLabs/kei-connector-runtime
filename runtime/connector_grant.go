package runtime

import (
	"context"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/invoke"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
)

// ConnectorGrant adapts the local PDP's connector decision to the serve
// daemon's POST /v1/commands:run route: it decides one credential reference
// with the PDP and the session subject, and the grant carries the connector's
// bundle descriptor (HAI-378) from the same bundle the decision used.
func (l *LocalPDP) ConnectorGrant(ctx context.Context, c invoke.DaemonCall) (invoke.Grant, error) {
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
