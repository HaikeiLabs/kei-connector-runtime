package policybundle

import (
	bundle "github.com/HaikeiLabs/kei-connector-contracts/bundle"
)

// Connector is a policy_set.connectors entry: a workspace connector the bundle
// knows, with its provider and declared capabilities. In a v2 bundle the entry
// is also the connector's non-secret descriptor (ADR-034, HAI-378 amendment):
// where its credential lives and its non-secret config, never a credential.
// v1 entries carry only id, provider and capabilities.
type Connector = bundle.Connector

// MCPDescriptor is the mcp block of a v2 connector descriptor (ADR-036 §4.3).
type MCPDescriptor = bundle.MCPDescriptor

// MCPCredentialField is one credential_fields entry of a secret_ref mcp
// descriptor (contract "mcp.credential_fields exact schema"): the secret at
// kei://connectors/<connector id>/<field> is sent in header, after prefix.
// It never carries a value.
type MCPCredentialField = bundle.MCPCredentialField

// MCPApprovedTool is one approved tool of an mcp descriptor (ADR-036 §4.3).
// approved_tools is sorted by name.
type MCPApprovedTool = bundle.MCPApprovedTool

// ConnectorCapability is one declared capability of a bundle connector.
type ConnectorCapability = bundle.ConnectorCapability

// Connector returns the bundle's connector entry with id.
func (v *Verified) Connector(id string) (Connector, bool) {
	return v.toBundle().Connector(id)
}

// CarriesConnectorDescriptors reports whether the bundle is v2 and its policy
// set has a connectors section. Without one (an older catalog) the runtime
// keeps its pre-descriptor behavior; with one, every routed connector must
// have an entry.
func (v *Verified) CarriesConnectorDescriptors() bool {
	return v.toBundle().CarriesConnectorDescriptors()
}

// MCPConnector returns the bundle's mcp connector descriptor whose slug is
// slug (ADR-036 §4.3, §4.5 step 5). The closed v2 schema guarantees an mcp
// descriptor has its mcp block.
func (v *Verified) MCPConnector(slug string) (Connector, bool) {
	return v.toBundle().MCPConnector(slug)
}

// MCPHosts returns host:port of every mcp descriptor URL in the bundle, the
// only upstream destinations the MCP route may dial (ADR-036 §4.10).
func (v *Verified) MCPHosts() []string {
	return v.toBundle().MCPHosts()
}

// AgentBoundToConnector reports whether agent_connector_bindings binds agentID
// to connectorID, whatever the capabilities (ADR-036 §4.5 step 6).
func (v *Verified) AgentBoundToConnector(agentID, connectorID string) bool {
	return v.toBundle().AgentBoundToConnector(agentID, connectorID)
}
