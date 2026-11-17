package invoke

// Secret resolution for opaque_ref connector descriptors inside the serve
// daemon (ADR-034, HAI-378 amendment). The descriptor names only a
// kei://connectors/<id>/<field> reference and a backend kind; the
// backend-qualified location comes from the connector reference index that
// `kei-proxy credential sync` wrote, and the value from the tenant secret
// store, read with the runtime's own cloud identity. The value is returned to
// the caller that applies it to the provider request and is never logged,
// encoded, or part of an error.

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/credentials"
	runtimecredentials "github.com/HaikeiLabs/kei-connector-runtime/internal/credentials"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

// Descriptor is the catalog's non-secret connector metadata on an allow, plus
// the secret backend an opaque_ref resolves in.
type Descriptor struct {
	contract.Metadata
	CredentialBackend string `json:"credential_backend,omitempty"`
	// CredentialSecretRef is where the control plane's connector secret
	// delivery wrote the credential (HAI-262), when it did.
	CredentialSecretRef string `json:"credential_secret_ref,omitempty"`
}

// SecretResolver resolves an opaque_ref bundle descriptor's credential inside
// the serve daemon.
type SecretResolver struct {
	// IndexPath is the connector reference index (credentials.ConnectorIndexPath).
	IndexPath string
	Store     credentials.Store
	// Timeout bounds one secret-store read; zero means credentials.DefaultTimeout.
	Timeout time.Duration
}

// SecretError is a fail-closed descriptor credential outcome with a reason
// code from the ADR-034 failure table. It never carries a reference or value.
type SecretError struct {
	Code   string
	Reason string
}

func (e *SecretError) Error() string { return e.Code + ": " + e.Reason }

const connectorRefPrefix = "kei://connectors/"

// ParseConnectorRef splits a kei://connectors/<connector id>/<field> reference.
func ParseConnectorRef(ref string) (connectorID, field string, ok bool) {
	rest, found := strings.CutPrefix(ref, connectorRefPrefix)
	if !found {
		return "", "", false
	}
	connectorID, field, found = strings.Cut(rest, "/")
	if !found || connectorID == "" || field == "" || strings.Contains(field, "/") {
		return "", "", false
	}
	return connectorID, field, true
}

// IsExternalRef reports whether a descriptor credential_ref is the
// customer's own secret (an external credential_ref, HAI-1000) rather than a
// kei://connectors reference.
func IsExternalRef(ref string) bool {
	return ref != "" && !strings.HasPrefix(ref, connectorRefPrefix)
}

// CheckExternalField reports whether field of descriptor c, whose
// credential_ref is external, was resolved by credential sync: the connector
// reference index must hold an External entry for exactly that connector and
// field, in the descriptor's backend, naming the descriptor's ref. Otherwise
// it returns a *SecretError (unresolved_reference, credential_backend_mismatch
// or credential_unavailable). It reads no secret value.
func (r SecretResolver) CheckExternalField(c policybundle.Connector, field string) error {
	if !IsExternalRef(c.CredentialRef) || c.CredentialBackend == "" {
		return &SecretError{"unresolved_reference", "the reference does not name the connector's credential field"}
	}
	if r.IndexPath == "" {
		return &SecretError{"credential_unavailable", "the connector credential is not available"}
	}
	entry, err := runtimecredentials.ReadConnectorReference(r.IndexPath, c.ID, field)
	if err != nil || !entry.External {
		return &SecretError{"unresolved_reference", "the reference does not name a credential resolved for this connector"}
	}
	if entry.SecretBackend != c.CredentialBackend {
		return &SecretError{"credential_backend_mismatch", "the delivered credential does not match the descriptor"}
	}
	if !runtimecredentials.ExternalReferenceNames(entry, c.CredentialRef) {
		return &SecretError{"unresolved_reference", "the reference does not name a credential resolved for this connector"}
	}
	return nil
}

// Resolve returns the credential value for descriptor c, or a *SecretError.
// Nothing is retried, and no other backend is tried.
func (r SecretResolver) Resolve(ctx context.Context, c policybundle.Connector) (string, error) {
	if contract.CredentialSource(c.CredentialSource) != contract.CredentialSourceOpaqueRef {
		return "", &SecretError{"descriptor_invalid", "the connector does not use a tenant-stored credential"}
	}
	if c.CredentialBackend == "" {
		return "", &SecretError{"descriptor_invalid", "the descriptor's credential reference does not name this connector"}
	}
	var lookup func() (runtimecredentials.ConnectorReference, error)
	if connectorID, field, ok := ParseConnectorRef(c.CredentialRef); ok {
		if connectorID != c.ID {
			return "", &SecretError{"descriptor_invalid", "the descriptor's credential reference does not name this connector"}
		}
		lookup = func() (runtimecredentials.ConnectorReference, error) {
			return runtimecredentials.ReadConnectorReference(r.IndexPath, connectorID, field)
		}
	} else if c.CredentialRef != "" && !strings.HasPrefix(c.CredentialRef, connectorRefPrefix) {
		// An external credential_ref (HAI-1000): the customer's own secret,
		// found only once credential sync resolved it for this connector.
		lookup = func() (runtimecredentials.ConnectorReference, error) {
			return runtimecredentials.ReadExternalConnectorReference(r.IndexPath, c.ID, c.CredentialBackend, c.CredentialRef)
		}
	} else {
		return "", &SecretError{"descriptor_invalid", "the descriptor's credential reference does not name this connector"}
	}
	if r.IndexPath == "" || r.Store == nil {
		return "", &SecretError{"credential_unavailable", "the connector credential is not available"}
	}
	entry, err := lookup()
	if errors.Is(err, runtimecredentials.ErrConnectorReferenceMismatch) {
		return "", &SecretError{"credential_backend_mismatch", "the delivered credential does not match the descriptor"}
	}
	if err != nil {
		return "", &SecretError{"credential_unavailable", "the connector credential has not been delivered to this runtime"}
	}
	if entry.SecretBackend != c.CredentialBackend {
		return "", &SecretError{"credential_backend_mismatch", "the delivered credential does not match the descriptor"}
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = credentials.DefaultTimeout
	}
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	value, err := r.Store.Get(lookupCtx, entry.SecretBackend, entry.SecretRef)
	if err != nil || value == nil || *value == "" {
		return "", &SecretError{"credential_unavailable", "the connector credential is not available"}
	}
	return *value, nil
}
