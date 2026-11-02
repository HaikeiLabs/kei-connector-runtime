package runtime

import "github.com/HaikeiLabs/kei-connector-contracts/contract"

// Credential kinds of a decision audit record (kei-connector-contracts
// audit.CredentialKind).
const (
	CredentialKindSecretStore = "secret_store"
	CredentialKindOAuth       = "oauth"
)

// connectorCredentialKind is the credential kind of a credential the release
// route handed out for connectorID: the connector's bundle descriptor names
// its credential_source (opaque_ref is secret_store, oauth is oauth). A bundle
// without a descriptor for it released a session credential, which the
// identity service issues as an OAuth credential.
func (l *LocalPDP) connectorCredentialKind(connectorID string) string {
	if e := l.evaluator.Load(); e != nil {
		if verified, ok := e.Bundle(); ok {
			if c, found := verified.Connector(connectorID); found && c.CredentialSource != "" {
				switch contract.CredentialSource(c.CredentialSource) {
				case contract.CredentialSourceOpaqueRef:
					return CredentialKindSecretStore
				case contract.CredentialSourceOAuth:
					return CredentialKindOAuth
				}
			}
		}
	}
	return CredentialKindOAuth
}
