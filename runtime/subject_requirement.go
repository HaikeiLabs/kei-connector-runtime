package runtime

import "github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"

// AuthorizeNeedsSubject reports whether a tool authorization must resolve the
// caller's subject before evaluating the bundle. Identity is only for
// credentials: it must when the tool releases a credential (a registry
// service) or is bound to a connector capability, or when a policy reached for
// the call matches on subject attributes. Any other tool is decided locally
// with no subject and no subject-resolution request.
func AuthorizeNeedsSubject(bundle *policybundle.Verified, registry ToolRegistry, tool, action, resource, agentID string) bool {
	if bundle == nil {
		return false // AuthorizeTool denies without a bundle.
	}
	if registry != nil && registry.Service(tool) != "" {
		return true
	}
	return bundle.SubjectRequired(policybundle.Call{Tool: tool, Action: action, Resource: resource, AgentID: agentID})
}
