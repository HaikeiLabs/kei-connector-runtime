package run

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Credential kinds of an access record (kei-connector-contracts
// audit.CredentialKind).
const (
	credentialKindSecretStore = "secret_store"
	credentialKindOAuth       = "oauth"
)

// credentialAccessRecord is the decision audit record the daemon writes for
// each connector whose credential it put into a child's environment. Its
// fields are the runtime decision record's (runtime.DecisionEvent), so the
// collector ships it to the catalog's audit:flush like any decision. It
// carries no credential value, no secret location and no session status.
type credentialAccessRecord struct {
	SpanID           string    `json:"span_id"`
	InvokedAt        time.Time `json:"invoked_at"`
	InvokingSubject  string    `json:"invoking_subject"`
	DelegationDepth  int       `json:"delegation_depth"`
	AgentID          string    `json:"agent_id"`
	Framework        string    `json:"framework"`
	ToolName         string    `json:"tool_name"`
	ResourcesTouched []string  `json:"resources_touched"`
	Decision         string    `json:"decision"`
	CredentialKind   string    `json:"credential_kind"`
}

// appendCredentialAccess writes one access record per connector in refs: the
// kind is secret_store for a tenant-stored secret (an opaque_ref descriptor)
// and oauth for the session's OAuth credential. subject is the linked session
// user every reference was authorized for.
func (d *Daemon) appendCredentialAccess(at time.Time, subject, agentID string, refs []resolvedRef) {
	if d.AppendAudit == nil || len(refs) == 0 {
		return
	}
	type access struct {
		kind      string
		resources []string
	}
	byConnector := map[string]*access{}
	var order []string
	for _, r := range refs {
		kind := credentialKindOAuth
		if r.secret != nil {
			kind = credentialKindSecretStore
		}
		a, ok := byConnector[r.ref.connectorID]
		if !ok {
			a = &access{kind: kind}
			byConnector[r.ref.connectorID] = a
			order = append(order, r.ref.connectorID)
		}
		a.resources = appendUnique(a.resources, "kei://connectors/"+r.ref.connectorID+"/"+r.ref.field)
	}
	for _, connectorID := range order {
		a := byConnector[connectorID]
		record, err := json.Marshal(credentialAccessRecord{
			SpanID: uuid.NewString(), InvokedAt: at, InvokingSubject: "user:" + subject,
			AgentID: agentID, Framework: "kei-proxy-run", ToolName: "connector:" + connectorID + "/" + runCapability,
			ResourcesTouched: a.resources, Decision: "allow", CredentialKind: a.kind,
		})
		if err != nil {
			continue
		}
		_ = d.AppendAudit(record)
	}
}
