package invoke

// Decision types shared by the serve daemon's credentialed connector routes
// (ADR-034, HAI-346). The commands:run runner (internal/run) asks the local
// PDP for a Grant per credential reference and resolves descriptor secrets
// through SecretResolver. The POST /v1/connectors:invoke handler that also
// used these types was removed by HAI-724.

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/credrelease"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

// IsSessionConnector reports whether connector c's credential is the session
// subject's own OAuth connection, released by I11 under the provider's name:
// its bundle descriptor says credential_source oauth and account_model
// per_user. The bundle alone decides (HAI-1050); a nil connector or one
// without those fields (a bundle without descriptors, from an older catalog)
// is not a session connector, so the daemon denies it.
func IsSessionConnector(c *policybundle.Connector) bool {
	return c != nil && c.CredentialSource == "oauth" && c.AccountModel == "per_user"
}

// Grant is the daemon's local decision for one connector call.
type Grant struct {
	Allow      bool
	V2Tool     bool
	ReasonCode string
	Reason     string
	Enrollment json.RawMessage
	// HasSession is false when there is no session at all.
	HasSession bool
	// Subject is the linked session user id the decision was made for, or "".
	Subject string
	AgentID string
	// Provider and Capabilities are the bundle's connector entry; Provider is
	// "" when the bundle does not know the connector.
	Provider     string
	ConnectorID  string
	Capabilities []string
	TenantID     string
	WorkspaceID  string
	// Connector is the bundle's descriptor for the connector (HAI-378), from
	// the same bundle as the decision, or nil. Descriptors reports whether the
	// bundle carries descriptors at all: without them the bundle does not say
	// where a credential lives, so the daemon denies credentialed calls.
	Connector   *policybundle.Connector
	Descriptors bool
}

// DaemonCall is what the daemon asks its PDP to decide. Session is the id of
// the session the call runs in ("" for the legacy default session).
type DaemonCall struct {
	Session                                    string
	ConnectorID, Capability, Resource, AgentID string
	ToolName                                   string
}

// ReasonSessionNotFound is the PDP's deny reason for a session id that is
// not live (pdp.ReasonSessionNotFound).
const ReasonSessionNotFound = "session_not_found"

// denial is a fail-closed outcome with a contract reason code.
type denial struct {
	code   string
	reason string
}

func deny(code, reason string) *denial { return &denial{code: code, reason: reason} }

// CredentialDenial maps a credential store refusal to a reason code and
// reason, and to a connect hint when reconnecting the provider would fix it.
func CredentialDenial(err error) (code, reason string, connect *json.RawMessage) {
	dn, connect := credentialDenial(err)
	return dn.code, dn.reason, connect
}

func credentialDenial(err error) (*denial, *json.RawMessage) {
	var se *SecretError
	if errors.As(err, &se) {
		return deny(se.Code, se.Reason), nil
	}
	var de *credrelease.DeniedError
	if !errors.As(err, &de) {
		return deny("credential_unavailable", "session credential is not available"), nil
	}
	var dn *denial
	switch de.Reason {
	case credrelease.ReasonNoSession:
		dn = deny("no_session", "the session ended or changed during the call")
	case credrelease.ReasonNotConnected:
		dn = deny("connector_not_connected", "the session subject has not connected this provider")
	case credrelease.ReasonReconnectRequired, credrelease.ReasonMaxLifetimeExceeded, credrelease.ReasonProviderUnauthorized:
		dn = deny("connector_reconnect_required", "the provider connection must be reconnected")
	case "SUBJECT_UNLINKED":
		dn = deny("subject_unlinked", "the session subject is not linked")
	default:
		dn = deny("credential_unavailable", "session credential is not available")
	}
	if !de.Connect() {
		return dn, nil
	}
	hint, _ := json.Marshal(map[string]string{"provider": de.Provider, "reason": de.Reason})
	raw := json.RawMessage(hint)
	return dn, &raw
}

// UseSecret runs fn with descriptor c's tenant-stored credential. The value
// is in scope only while fn runs.
func UseSecret(ctx context.Context, r SecretResolver, c policybundle.Connector, fn func(value string) error) error {
	value, err := r.Resolve(ctx, c)
	if err != nil {
		return err
	}
	if err := fn(value); err != nil && !errors.Is(err, credrelease.ErrProviderUnauthorized) {
		return err
	}
	return nil
}
