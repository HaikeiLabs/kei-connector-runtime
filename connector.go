package connectorruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/crm"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/invoke"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/secrets"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/session"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
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
				return keiruntime.NewAuditSpool(cfg.AuditPath, cfg.AuditMaxBytes).Append(keiruntime.EventClassDecision, record)
			},
		}
		if cfg.IsRuntime() {
			src := session.NewSocketSubjectSource(runtimeSocketPathFromEnv(), cfg.RuntimeToken)
			env.SubjectSource = src
			if cfg.CredentialReleaseMode == "identity" {
				// L3a: read pre-resolved credential from the daemon socket
				// instead of creating a per-invoke I11 client.
				env.StaticCredential = daemonSessionCredential(runtimeSocketPathFromEnv(), cfg.RuntimeToken)
			}
		}
		return invoke.Run(args[1:], env, os.Stdout, os.Stderr)
	}
	fmt.Fprintln(os.Stderr, "Error: unknown connector command\n\nUsage: kei-proxy connector invoke --connector <id> --capability <name> --action <action> --resource <resource>")
	return 1
}

// daemonSessionCredential reads the pre-resolved session credential from the
// serve daemon's Unix socket (L3a). It returns the credential string on
// success, or an empty string (and logs the error) if the daemon has no
// credential or is unreachable. Returning empty keeps the child process
// running in legacy fallback mode.
func daemonSessionCredential(socketPath, runtimeToken string) string {
	if socketPath == "" {
		return ""
	}
	req, err := http.NewRequest(http.MethodGet, "http://localhost/v1/session/credential", nil)
	if err != nil {
		slog.Warn("daemon credential request build failed", "error", err)
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+runtimeToken)
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	}}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		slog.Debug("daemon credential not available (daemon may not have one)", "error", err)
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		slog.Debug("daemon credential not available", "status", resp.StatusCode)
		return ""
	}
	var out struct {
		Credential string `json:"credential"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		slog.Warn("daemon credential decode failed", "error", err)
		return ""
	}
	return out.Credential
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
