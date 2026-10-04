package connectorruntime

import (
	"encoding/json"
	"strings"
	"testing"

	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

// TestAuthorizeAuditEventNeverCarriesCredential is the transport redaction
// guarantee: the audit record emitted for an allow decision never includes the
// served credential, even though the output carries it for the agent.
func TestAuthorizeAuditEventNeverCarriesCredential(t *testing.T) {
	const secret = "crm-transport-key-SECRET"
	p := keiruntime.AuthorizeParams{
		User: "u-1", Tool: "crm", AgentID: "a-1", Framework: "test",
		InvokingSubject: "u-1", Resources: []string{"crm:repo:leads"},
	}
	resp := &AuthorizeResponse{Decision: "allow", PolicyID: "pol-1", OrgID: strPtr("org-1")}
	out := AuthorizeOutput{Decision: "allow", Service: "crm", Credential: &CredentialResponse{Value: secret}}
	event := keiruntime.BuildDecisionEvent(p, resp, out, "crm:repo:leads")
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatalf("audit event leaked the credential: %s", data)
	}
}

func strPtr(s string) *string { return &s }
