package policybundle

import (
	"encoding/json"
	"sort"
	"time"
)

// ConnectorToolSummary is the non-secret registration of one connector_binding
// tool in a verified v2 bundle: which connector it routes through, the
// binding's pinned version and resource template, and its plan's operation
// ids. It is what a harness needs to configure the tool, never how to reach
// the connector's credential.
type ConnectorToolSummary struct {
	Name             string
	ConnectorID      string
	BindingVersion   string
	ResourceTemplate string
	OperationIDs     []string
}

// V2ConnectorToolSummaries lists the connector_binding tools that
// V2ConnectorTool would resolve at now (valid plan, fresh subject snapshot),
// sorted by name. It is empty for a non-v2 or stale bundle.
func (v *Verified) V2ConnectorToolSummaries(now time.Time) []ConnectorToolSummary {
	if v == nil || v.Payload.Schema != "kei.policy-bundle/v2" || !v.SubjectSnapshotFresh(now) {
		return nil
	}
	var set v2PolicySet
	if strictJSON(v.Payload.PolicySet, &set) != nil {
		return nil
	}
	var out []ConnectorToolSummary
	for _, tool := range set.Tools {
		if tool.Route.ConnectorBinding == nil || len(tool.Plan) == 0 || ValidateV2Plan(tool.V2Tool) != nil {
			continue
		}
		var plan struct {
			Operations []struct {
				ID string `json:"id"`
			} `json:"operations"`
		}
		if json.Unmarshal(tool.Plan, &plan) != nil {
			continue
		}
		ids := make([]string, 0, len(plan.Operations))
		for _, op := range plan.Operations {
			ids = append(ids, op.ID)
		}
		out = append(out, ConnectorToolSummary{
			Name: tool.Name, ConnectorID: tool.Route.ConnectorBinding.ConnectorID,
			BindingVersion: tool.Route.ConnectorBinding.Version, ResourceTemplate: tool.Route.ConnectorBinding.ResourceTemplate,
			OperationIDs: ids,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
