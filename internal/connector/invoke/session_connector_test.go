package invoke

import (
	"testing"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

// HAI-1050: whether a connector's credential is the session subject's own
// OAuth connection is read from its bundle descriptor, not from contracts.
func TestIsSessionConnectorReadsDescriptorFields(t *testing.T) {
	for name, tc := range map[string]struct {
		c    *policybundle.Connector
		want bool
	}{
		"no descriptor":               {nil, false},
		"v1 entry without fields":     {&policybundle.Connector{ID: "c", Provider: "github"}, false},
		"oauth per_user":              {&policybundle.Connector{ID: "c", Provider: "github", CredentialSource: "oauth", AccountModel: "per_user"}, true},
		"oauth per_user unknown prov": {&policybundle.Connector{ID: "c", Provider: "postgres", CredentialSource: "oauth", AccountModel: "per_user"}, true},
		"oauth shared":                {&policybundle.Connector{ID: "c", Provider: "github", CredentialSource: "oauth", AccountModel: "shared"}, false},
		"oauth domain_delegation":     {&policybundle.Connector{ID: "c", Provider: "google_drive", CredentialSource: "oauth", AccountModel: "domain_delegation"}, false},
		"opaque_ref per_user":         {&policybundle.Connector{ID: "c", Provider: "http_api", CredentialSource: "opaque_ref", AccountModel: "per_user"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := IsSessionConnector(tc.c); got != tc.want {
				t.Fatalf("IsSessionConnector = %v, want %v", got, tc.want)
			}
		})
	}
}
