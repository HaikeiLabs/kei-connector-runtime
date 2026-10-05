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
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/auditcrypto"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/invoke"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/credentials"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/secrets"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/session"
	"github.com/google/uuid"
)

type runCredentialResolver interface {
	Resolve(context.Context, string, string) (value, connectURL string, err error)
}

type runCredentialBindingClient interface {
	Resolve(ctx context.Context, runtimeToken, userID, service string) (secretBackend, secretRef string, connectURL string, err error)
}

type runAuthorization interface {
	Authorize(context.Context, string, string, string) (*invoke.Response, error)
}

// Config contains runtime values needed by the run wrapper. AppendAudit writes
// one value-free run event into the shared runtime audit spool.
type Config struct {
	ABACURL, ABACSecret, RuntimeToken, RuntimeStateDir, ProviderUserID string
	ControlPlaneURL, SocketPath                                        string
	AppendAudit                                                        func([]byte) error
	AuditCrypto                                                        *auditcrypto.Provider
	// DaemonSocket, when set (KEI_CREDENTIAL_RELEASE=identity), makes run a
	// thin client of the serve daemon's POST /v1/commands:run on this Unix
	// socket: the daemon resolves the references and spawns the child, and
	// this process never holds a credential.
	DaemonSocket string
}

type catalogRunAuthorization struct{ cfg Config }

func (a catalogRunAuthorization) Authorize(ctx context.Context, connectorID, field, resource string) (*invoke.Response, error) {
	client := invoke.NewClient(a.cfg.ABACURL, a.cfg.ABACSecret, 10*time.Second)
	return client.Invoke(ctx, invoke.Request{HarnessToken: a.cfg.RuntimeToken, ConnectorID: connectorID, Capability: "credential", Action: "use", Resource: resource, TraceID: uuid.NewString(), AgentID: os.Getenv("KEI_PROXY_AGENT_ID"), Framework: "kei-proxy-run", ProviderUserID: a.cfg.ProviderUserID})
}

type deliveredRunResolver struct {
	cfg               Config
	store             secrets.Store
	authorization     runAuthorization
	credentialBinding runCredentialBindingClient
	subjectSource     session.SubjectSource
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
	source := response.Connector.EffectiveCredentialSource()
	if source == contract.CredentialSourceOAuth {
		return r.resolveOAuth(ctx, connectorID, field, response)
	}
	if source != contract.CredentialSourceOpaqueRef {
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

func (r deliveredRunResolver) resolveOAuth(ctx context.Context, connectorID, field string, response *invoke.Response) (string, string, error) {
	if r.subjectSource == nil {
		return "", "", runReasonError{"subject_unlinked"}
	}
	userID, err := r.subjectSource.Subject(ctx)
	if err != nil || userID == "" {
		return "", "", runReasonError{"subject_unlinked"}
	}
	if r.credentialBinding == nil {
		return "", "", runReasonError{"unresolved_reference"}
	}
	provider := string(response.Connector.Provider)
	if provider == "" {
		return "", "", runReasonError{"unresolved_reference"}
	}
	backend, ref, connectURL, err := r.credentialBinding.Resolve(ctx, r.cfg.RuntimeToken, userID, provider)
	if err != nil {
		if connectURL != "" {
			return "", connectURL, runReasonError{"connect_required"}
		}
		return "", "", runReasonError{"unresolved_reference"}
	}
	value, err := r.store.Get(ctx, backend, ref)
	if err != nil || value == nil || *value == "" {
		return "", "", runReasonError{"unresolved_reference"}
	}
	return *value, "", nil
}

type httpCredentialBindingClient struct {
	baseURL string
	client  *http.Client
}

func newHTTPCredentialBindingClient(baseURL string) *httpCredentialBindingClient {
	return &httpCredentialBindingClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *httpCredentialBindingClient) Resolve(ctx context.Context, runtimeToken, userID, service string) (string, string, string, error) {
	endpoint := c.baseURL + "/api/v1/runtime/credential-bindings/" + url.PathEscape(userID) + "/services/" + url.PathEscape(service)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", "", "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+runtimeToken)
	resp, err := c.client.Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		connectURL := c.baseURL + "/credentials/connect?service=" + url.QueryEscape(service) + "&user_id=" + url.QueryEscape(userID)
		return "", "", connectURL, errors.New("not found")
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", "", fmt.Errorf("credential binding returned status %d", resp.StatusCode)
	}
	var descriptor struct {
		SecretBackend string `json:"secret_backend"`
		SecretRef     string `json:"secret_ref"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&descriptor); err != nil {
		return "", "", "", fmt.Errorf("decode response: %w", err)
	}
	if descriptor.SecretBackend == "" || descriptor.SecretRef == "" {
		return "", "", "", fmt.Errorf("incomplete response")
	}
	return descriptor.SecretBackend, descriptor.SecretRef, "", nil
}

type runReasonError struct{ reason string }

func (e runReasonError) Error() string { return e.reason }

type runAuditEvent struct {
	Schema          string    `json:"schema"`
	EventClass      string    `json:"event_class"`
	ObservedAt      time.Time `json:"observed_at"`
	ConnectorIDs    []string  `json:"connector_ids,omitempty"`
	Fields          []string  `json:"fields,omitempty"`
	Command         string    `json:"command"`
	ArgsDigest      string    `json:"args_digest"`
	DigestKeyID     string    `json:"digest_key_id,omitempty"`
	ArgsCiphertext  string    `json:"args_ciphertext,omitempty"`
	RecipientKeyIDs []string  `json:"recipient_key_ids,omitempty"`
	Outcome         string    `json:"outcome"`
	ExitCode        int       `json:"exit_code"`
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
			fmt.Fprintf(stderr, "Connector credential %s/%s does not match --connector.\n", ref.connectorID, ref.field)
			appendRunAudit(stderr, cfg, connectorIDs, fields, "", childArgs, "credential_reference_mismatch", 1)
			return 1
		}
		secret, connectURL, err := resolver.Resolve(context.Background(), ref.connectorID, ref.field)
		if err != nil || secret == "" {
			if connectURL != "" {
				fmt.Fprintf(stderr, "Connector credential %s/%s is not connected. Open this link privately: %s\n", ref.connectorID, ref.field, connectURL)
			} else {
				reason := "unresolved_reference"
				var coded runReasonError
				if errors.As(err, &coded) {
					reason = coded.reason
				}
				fmt.Fprintf(stderr, "Connector credential %s/%s unavailable (%s).\n", ref.connectorID, ref.field, reason)
			}
			reason := "unresolved_reference"
			var coded runReasonError
			if errors.As(err, &coded) {
				reason = coded.reason
			}
			appendRunAudit(stderr, cfg, connectorIDs, fields, childArgs[0], childArgs, reason, 1)
			return 1
		}
		childEnv = append(childEnv, key+"="+secret)
		secretsToMask = append(secretsToMask, secret)
	}
	if len(secretsToMask) == 0 {
		fmt.Fprintln(stderr, "run requires at least one kei://connectors/<id>/<field> environment reference")
		appendRunAudit(stderr, cfg, nil, nil, childArgs[0], childArgs, "credential_reference_missing", 2)
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
	appendRunAudit(stderr, cfg, connectorIDs, fields, childArgs[0], childArgs, outcome, exitCode)
	return exitCode
}

// Run executes one child command with governed connector credentials.
func Run(args []string, stdout, stderr io.Writer, cfg Config) int {
	if cfg.RuntimeToken == "" {
		fmt.Fprintln(stderr, "run requires KEI_RUNTIME_TOKEN")
		return 1
	}
	if cfg.DaemonSocket != "" {
		return runViaDaemon(args, stdout, stderr, cfg, os.Environ())
	}
	store, err := secrets.NewStore()
	if err != nil {
		fmt.Fprintln(stderr, "run credential store is unavailable")
		return 1
	}
	var credBinding runCredentialBindingClient
	if cfg.ControlPlaneURL != "" {
		credBinding = newHTTPCredentialBindingClient(cfg.ControlPlaneURL)
	}
	var subjectSource session.SubjectSource
	if cfg.SocketPath != "" {
		subjectSource = session.NewSocketSubjectSource(cfg.SocketPath, cfg.RuntimeToken)
	}
	resolver := deliveredRunResolver{cfg: cfg, store: store, authorization: catalogRunAuthorization{cfg: cfg}, credentialBinding: credBinding, subjectSource: subjectSource}
	return runCommand(args, stdout, stderr, cfg, os.Environ(), resolver, nil)
}

func appendRunAudit(stderr io.Writer, cfg Config, connectorIDs, fields []string, command string, argv []string, outcome string, exitCode int) {
	argvBytes, err := json.Marshal(argv)
	if err != nil {
		fmt.Fprintf(stderr, "audit: failed to marshal argv for run audit event: %v\n", err)
		return
	}
	var argsDigest, digestKeyID string
	var argsCiphertext string
	var recipientKeyIDs []string
	if cfg.AuditCrypto != nil {
		argsDigest, digestKeyID = cfg.AuditCrypto.Digest(argvBytes)
		argsCiphertext, recipientKeyIDs = cfg.AuditCrypto.Encrypt(argvBytes)
	} else {
		sum := sha256.Sum256(argvBytes)
		argsDigest = "sha256:" + hex.EncodeToString(sum[:])
	}
	event, err := json.Marshal(runAuditEvent{Schema: "kei.proxy-run-event/v1", EventClass: "credential", ObservedAt: time.Now().UTC(), ConnectorIDs: connectorIDs, Fields: fields, Command: command, ArgsDigest: argsDigest, DigestKeyID: digestKeyID, ArgsCiphertext: argsCiphertext, RecipientKeyIDs: recipientKeyIDs, Outcome: outcome, ExitCode: exitCode})
	if err != nil {
		fmt.Fprintf(stderr, "audit: failed to marshal run audit event: %v\n", err)
		return
	}
	if cfg.AppendAudit != nil {
		if err := cfg.AppendAudit(event); err != nil {
			fmt.Fprintf(stderr, "audit: failed to append credential audit record: %v\n", err)
		}
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
