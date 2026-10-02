package run

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/invoke"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/credentials"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/secrets"
	"github.com/google/uuid"
)

type runCredentialResolver interface {
	Resolve(context.Context, string, string) (value, connectURL string, err error)
}

type runAuthorization interface {
	Authorize(context.Context, string, string, string) (*invoke.Response, error)
}

// Config contains runtime values needed by the run wrapper. AppendAudit writes
// one value-free run event into the shared runtime audit spool.
type Config struct {
	ABACURL, ABACSecret, RuntimeToken, RuntimeStateDir, ProviderUserID string
	AppendAudit                                                        func([]byte) error
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

type catalogRunAuthorization struct{ cfg Config }

func (a catalogRunAuthorization) Authorize(ctx context.Context, connectorID, field, resource string) (*invoke.Response, error) {
	client := invoke.NewClient(a.cfg.ABACURL, a.cfg.ABACSecret, 10*time.Second)
	return client.Invoke(ctx, invoke.Request{HarnessToken: a.cfg.RuntimeToken, ConnectorID: connectorID, Capability: "credential", Action: "use", Resource: resource, TraceID: uuid.NewString(), InvokingSubject: envOr("KEI_PROXY_INVOKING_SUBJECT", ""), UserID: envOr("KEI_PROXY_USER_ID", ""), AgentID: envOr("KEI_PROXY_AGENT_ID", ""), Framework: "kei-proxy-run", ProviderUserID: a.cfg.ProviderUserID})
}

type deliveredRunResolver struct {
	cfg           Config
	store         secrets.Store
	authorization runAuthorization
}

func (r deliveredRunResolver) Resolve(ctx context.Context, connectorID, field string) (string, string, error) {
	resource := "kei://connectors/" + connectorID + "/" + field
	response, err := r.authorization.Authorize(ctx, connectorID, field, resource)
	if err != nil {
		return "", "", runReasonError{"policy_unavailable"}
	}
	if response == nil || response.Decision != "allow" {
		return "", "", runReasonError{"policy_denied"}
	}
	if response.Connector == nil || response.Connector.ID != connectorID {
		return "", "", runReasonError{"unresolved_reference"}
	}
	if response.Connector.EffectiveCredentialSource() == contract.CredentialSourceOAuth {
		return "", "", runReasonError{"oauth_not_supported"}
	}
	if response.Connector.EffectiveCredentialSource() != contract.CredentialSourceOpaqueRef {
		return "", "", runReasonError{"unresolved_reference"}
	}
	entry, err := credentials.ReadConnectorReference(filepath.Join(r.cfg.RuntimeStateDir, "connector-credentials.json"), connectorID, field)
	if err != nil || entry.SecretBackend != response.Connector.CredentialBackend || entry.SecretRef != response.Connector.CredentialSecretRef || response.Connector.CredentialRef == "" || !strings.HasSuffix(entry.SecretRef, "/"+response.Connector.CredentialRef) {
		return "", "", runReasonError{"unresolved_reference"}
	}
	value, err := r.store.Get(ctx, entry.SecretBackend, entry.SecretRef)
	if err != nil || value == nil || *value == "" {
		return "", "", runReasonError{"unresolved_reference"}
	}
	return *value, "", nil
}

type runReasonError struct{ reason string }

func (e runReasonError) Error() string { return e.reason }

type runAuditEvent struct {
	Schema       string    `json:"schema"`
	ObservedAt   time.Time `json:"observed_at"`
	ConnectorIDs []string  `json:"connector_ids,omitempty"`
	Fields       []string  `json:"fields,omitempty"`
	Command      string    `json:"command"`
	ArgsDigest   string    `json:"args_digest"`
	Outcome      string    `json:"outcome"`
	ExitCode     int       `json:"exit_code"`
}

func runCommand(args []string, stdout, stderr io.Writer, cfg Config, parentEnv []string, resolver runCredentialResolver, execFn func(string, []string, []string) int) int {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	connectorID := flags.String("connector", "", "connector id for resolved credentials")
	sep := -1
	for i, arg := range args {
		if arg == "--" {
			sep = i
			break
		}
	}
	if sep < 0 || flags.Parse(args[:sep]) != nil || flags.NArg() != 0 || sep+1 >= len(args) {
		fmt.Fprintln(stderr, "run requires [--connector id] -- <command> [args...]")
		return 2
	}
	childArgs := append([]string(nil), args[sep+1:]...)
	if childArgs[0] == "" {
		fmt.Fprintln(stderr, "run command is required")
		return 2
	}
	if resolver == nil {
		fmt.Fprintln(stderr, "run credential resolver is unavailable")
		return 1
	}

	childEnv := make([]string, 0, len(parentEnv))
	var secretsToMask []string
	var connectorIDs, fields []string
	for _, entry := range parentEnv {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		ref, isRef := parseConnectorCredentialRef(value)
		if !isRef {
			childEnv = append(childEnv, entry)
			continue
		}
		connectorIDs = appendUnique(connectorIDs, ref.connectorID)
		fields = appendUnique(fields, ref.field)
		if *connectorID != "" && *connectorID != ref.connectorID {
			fmt.Fprintln(stderr, "run credential reference does not match --connector")
			appendRunAudit(cfg, connectorIDs, fields, "", childArgs, "credential_reference_mismatch", 1)
			return 1
		}
		secret, connectURL, err := resolver.Resolve(context.Background(), ref.connectorID, ref.field)
		if err != nil || secret == "" {
			if connectURL != "" {
				fmt.Fprintf(stderr, "Connector credentials are not connected. Open this link privately: %s\n", connectURL)
			} else {
				reason := "unresolved_reference"
				var coded runReasonError
				if errors.As(err, &coded) {
					reason = coded.reason
				}
				fmt.Fprintf(stderr, "Connector credential unavailable (%s).\n", reason)
			}
			reason := "unresolved_reference"
			var coded runReasonError
			if errors.As(err, &coded) {
				reason = coded.reason
			}
			appendRunAudit(cfg, connectorIDs, fields, childArgs[0], childArgs, reason, 1)
			return 1
		}
		childEnv = append(childEnv, key+"="+secret)
		secretsToMask = append(secretsToMask, secret)
	}
	if len(secretsToMask) == 0 {
		fmt.Fprintln(stderr, "run requires at least one kei://connectors/<id>/<field> environment reference")
		appendRunAudit(cfg, nil, nil, childArgs[0], childArgs, "credential_reference_missing", 2)
		return 2
	}
	redactOut, redactErr := newRedactingWriter(stdout, secretsToMask), newRedactingWriter(stderr, secretsToMask)
	if execFn == nil {
		execFn = func(path string, argv, env []string) int {
			cmd := exec.Command(path, argv[1:]...)
			cmd.Env, cmd.Stdout, cmd.Stderr = env, redactOut, redactErr
			err := cmd.Run()
			if err == nil {
				return 0
			}
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				return exitErr.ExitCode()
			}
			return 127
		}
	}
	exitCode := execFn(childArgs[0], childArgs, childEnv)
	_ = redactOut.Close()
	_ = redactErr.Close()
	outcome := "success"
	if exitCode != 0 {
		outcome = "failure"
	}
	appendRunAudit(cfg, connectorIDs, fields, childArgs[0], childArgs, outcome, exitCode)
	return exitCode
}

// Run executes one child command with governed connector credentials.
func Run(args []string, stdout, stderr io.Writer, cfg Config) int {
	if cfg.RuntimeToken == "" {
		fmt.Fprintln(stderr, "run requires KEI_RUNTIME_TOKEN")
		return 1
	}
	store, err := secrets.NewStore()
	if err != nil {
		fmt.Fprintln(stderr, "run credential store is unavailable")
		return 1
	}
	resolver := deliveredRunResolver{cfg: cfg, store: store, authorization: catalogRunAuthorization{cfg: cfg}}
	return runCommand(args, stdout, stderr, cfg, os.Environ(), resolver, nil)
}

func appendRunAudit(cfg Config, connectorIDs, fields []string, command string, argv []string, outcome string, exitCode int) {
	argvBytes, _ := json.Marshal(argv)
	argsDigest := sha256.Sum256(argvBytes)
	event, _ := json.Marshal(runAuditEvent{Schema: "kei.proxy-run-event/v1", ObservedAt: time.Now().UTC(), ConnectorIDs: connectorIDs, Fields: fields, Command: command, ArgsDigest: "sha256:" + hex.EncodeToString(argsDigest[:]), Outcome: outcome, ExitCode: exitCode})
	if cfg.AppendAudit != nil {
		_ = cfg.AppendAudit(event)
	}
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

type connectorCredentialRef struct{ connectorID, field string }

func parseConnectorCredentialRef(raw string) (connectorCredentialRef, bool) {
	const prefix = "kei://connectors/"
	if !strings.HasPrefix(raw, prefix) {
		return connectorCredentialRef{}, false
	}
	parts := strings.Split(strings.TrimPrefix(raw, prefix), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.ContainsAny(raw, "?#\\") {
		return connectorCredentialRef{}, false
	}
	for _, part := range parts {
		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r)) {
				return connectorCredentialRef{}, false
			}
		}
	}
	return connectorCredentialRef{connectorID: parts[0], field: parts[1]}, true
}

type redactingWriter struct {
	out     io.Writer
	values  []string
	pending string
	hold    int
	closed  bool
}

func newRedactingWriter(out io.Writer, values []string) *redactingWriter {
	hold := 0
	for _, value := range values {
		if len(value) > hold {
			hold = len(value)
		}
	}
	return &redactingWriter{out: out, values: values, hold: hold}
}
func (w *redactingWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("redacting writer is closed")
	}
	w.pending += string(p)
	if len(w.pending) <= w.hold {
		return len(p), nil
	}
	// Redact before choosing a write boundary. A secret may start just before
	// that boundary and finish in the retained suffix.
	w.pending = w.mask(w.pending)
	if len(w.pending) <= w.hold {
		return len(p), nil
	}
	cut := len(w.pending) - w.hold
	// Do not split UTF-8 continuation bytes; redaction tokens are ASCII.
	for cut > 0 && cut < len(w.pending) && w.pending[cut]&0xc0 == 0x80 {
		cut--
	}
	if cut == 0 {
		return len(p), nil
	}
	chunk := w.pending[:cut]
	w.pending = w.pending[cut:]
	_, err := io.WriteString(w.out, chunk)
	return len(p), err
}
func (w *redactingWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	_, err := io.WriteString(w.out, w.mask(w.pending))
	w.pending = ""
	return err
}
func (w *redactingWriter) mask(value string) string {
	for _, secret := range w.values {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "[REDACTED]")
		}
	}
	return value
}
