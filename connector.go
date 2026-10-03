package connectorruntime

import (
	"errors"
	"fmt"
	"os"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/crm"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/invoke"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/secrets"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/session"
)

// runConnector dispatches the connector subcommand.
func runConnector(args []string) int {
	if len(args) > 0 && args[0] == "invoke" {
		cfg := configFromEnv()
		if cfg.IsRuntime() {
			if err := cfg.Validate(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				return 1
			}
		}
		env := invoke.Env{
			RuntimeToken:           cfg.RuntimeToken,
			RuntimeControlPlaneURL: cfg.RuntimeControlPlaneURL,
			ABACURL:                cfg.ABACURL,
			ABACSecret:             cfg.ABACSecret,
			ProviderUserID:         cfg.ProviderUserID,
			Stdin:                  os.Stdin,
			Store:                  connectorSecretStore(),
			BackendUnavailable:     func(err error) bool { return errors.Is(err, secrets.ErrUnavailable) },
			AssertionKey:           crm.KeyConfigFromEnv(),
			Audit: func(record []byte) error {
				if cfg.AuditPath == "" {
					return nil
				}
				return newAuditSpool(cfg.AuditPath, cfg.AuditMaxBytes).Append(eventClassDecision, record)
			},
		}
		if cfg.IsRuntime() {
			env.SubjectSource = session.NewSocketSubjectSource(runtimeSocketPathFromEnv(), cfg.RuntimeToken)
		}
		return invoke.Run(args[1:], env, os.Stdout, os.Stderr)
	}
	fmt.Fprintln(os.Stderr, "Error: unknown connector command\n\nUsage: kei-proxy connector invoke --connector <id> --capability <name> --action <action> --resource <resource>")
	return 1
}

// connectorSecretStore is the tenant secret store for connector credentials:
// the same backends model profiles use. Without one, opaque_ref connectors
// deny credential_backend_unavailable.
func connectorSecretStore() secrets.Store {
	store, err := secrets.NewStore()
	if err != nil {
		return nil
	}
	return store
}
