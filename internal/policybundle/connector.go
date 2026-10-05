package policybundle

// Connector is a policy_set.connectors entry: a workspace connector the bundle
// knows, with its provider and declared capabilities. It carries no config
// and no credential.
type Connector struct {
	ID           string                `json:"id"`
	Provider     string                `json:"provider"`
	Capabilities []ConnectorCapability `json:"capabilities"`
}

// ConnectorCapability is one declared capability of a bundle connector.
type ConnectorCapability struct {
	Name     string `json:"name"`
	Mutating bool   `json:"mutating"`
}

// Connector returns the bundle's connector entry with id.
func (v *Verified) Connector(id string) (Connector, bool) {
	set, err := v.decodePolicySet()
	if err != nil {
		return Connector{}, false
	}
	for _, c := range set.Connectors {
		if c.ID == id {
			return c, true
		}
	}
	return Connector{}, false
}
