package run

// The serve daemon's side of POST /v1/commands:run (ADR-034, owner option A,
// HAI-346 L3c). `kei-proxy run -- <cmd>` sends argv and its environment, in
// which kei://connectors/<id>/<field> values are credential references. The
// daemon authorizes each reference with its local PDP and the session
// subject, resolves it from the session-held credential, spawns the child
// with exactly the caller's environment plus the resolved values, and
// streams the child's stdout and stderr back with resolved values redacted,
// then its exit code. The credential reaches only the child's environment.
//
// Who uses it: this is the path for native CLI tools (gh, git, ...) run by
// Unix/local-process harnesses such as Claude Code, Codex and opencode,
// through `kei-proxy run -- <cmd>`. It runs inside the serve daemon with
// session-held credentials that never leave it.
//
// stdin is not passed through: the child reads an empty stdin (/dev/null).

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/auditcrypto"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/invoke"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/session"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

const (
	// DaemonRunPath is the socket route the daemon serves.
	DaemonRunPath       = "/v1/commands:run"
	daemonRunSchema     = "kei.command-run-request/v1"
	daemonStreamSchema  = "kei.command-run-stream/v1"
	maxDaemonRunRequest = 512 << 10
	// runCapability is the connector capability a credential reference is
	// authorized as, with resource kei://connectors/<id>/<field>; the same
	// capability the catalog decides for the legacy run path.
	runCapability = "credential"
)

// sessionCredentialFields are the reference fields a session OAuth credential
// can fill: its access token.
var sessionCredentialFields = map[string]bool{"token": true, "access_token": true}

// Daemon serves POST /v1/commands:run inside the serve daemon. The caller
// authenticates the request before ServeHTTP.
type Daemon struct {
	// Authorize decides one credential reference with the local PDP and the
	// session subject.
	Authorize func(context.Context, invoke.DaemonCall) (invoke.Grant, error)
	// UseCredential runs fn with the credential the named session holds for
	// subject and provider (credrelease.Store.Use); a session reaches only its
	// own credentials.
	UseCredential func(ctx context.Context, session, subject, provider string, fn func(token string) error) error
	AppendAudit   func([]byte) error
	AuditCrypto   *auditcrypto.Provider
	// Secrets resolves references to opaque_ref connectors from the bundle's
	// connector descriptors (HAI-378).
	Secrets invoke.SecretResolver
	// RouteKeys, when set, gives each run in a named session an MCP route
	// key in KEI_MCP_ROUTE_KEY (ADR-036 §4.4), and makes credential
	// references optional: `kei-proxy run -- <harness>` launches a harness.
	RouteKeys RouteKeys
}

// RouteKeys mints and revokes /mcp/{slug} route keys. Mint returns a
// *RouteKeyDenied when the session cannot have one.
type RouteKeys interface {
	Mint(sessionID, agentID, harnessKind string) (string, error)
	Revoke(key string)
}

// RouteKeyDenied is why a run's session gets no route key.
type RouteKeyDenied struct{ Code, Reason string }

func (e *RouteKeyDenied) Error() string { return e.Code + ": " + e.Reason }

// routeKeyEnv names the child environment variable that carries the key.
const routeKeyEnv = "KEI_MCP_ROUTE_KEY"

// harnessKindPattern is the shape of a harness kind (claude_code, codex, ...).
var harnessKindPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// daemonRunRequest is the route's body. Env is the caller's environment as
// KEY=VALUE entries; entries whose value is a kei://connectors reference are
// resolved, the rest pass to the child unchanged.
type daemonRunRequest struct {
	Schema    string   `json:"schema"`
	Argv      []string `json:"argv"`
	Env       []string `json:"env"`
	Dir       string   `json:"dir,omitempty"`
	Connector string   `json:"connector,omitempty"`
	AgentID   string   `json:"agent_id,omitempty"`
	// HarnessKind names the harness for harness:<kind> policy sources on the
	// MCP route (claude_code, codex, opencode, custom).
	HarnessKind string `json:"harness_kind,omitempty"`
}

// runFrame is one line of the response stream: a chunk of the child's output
// or, last, the outcome.
type runFrame struct {
	Stream string   `json:"stream,omitempty"` // stdout | stderr
	Data   []byte   `json:"data,omitempty"`
	Done   *runDone `json:"done,omitempty"`
}

type runDone struct {
	Schema     string           `json:"schema"`
	Decision   string           `json:"decision"` // allow | deny
	ReasonCode string           `json:"reason_code,omitempty"`
	Reason     string           `json:"reason,omitempty"`
	ExitCode   int              `json:"exit_code"`
	Connect    *json.RawMessage `json:"connect,omitempty"`
}

// frameWriter serializes frames from the child's two output streams.
type frameWriter struct {
	mu  sync.Mutex
	enc *json.Encoder
	rc  *http.ResponseController
}

func (f *frameWriter) write(frame runFrame) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enc.Encode(frame); err != nil {
		return err
	}
	return f.rc.Flush()
}

type streamWriter struct {
	frames *frameWriter
	stream string
}

func (s streamWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := s.frames.write(runFrame{Stream: s.stream, Data: append([]byte(nil), p...)}); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (d *Daemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req daemonRunRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxDaemonRunRequest))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.Schema != daemonRunSchema || dec.More() {
		writeRunError(w, http.StatusBadRequest, "request must be a "+daemonRunSchema+" object with no unknown fields")
		return
	}
	if len(req.Argv) == 0 || req.Argv[0] == "" {
		writeRunError(w, http.StatusBadRequest, "argv is required")
		return
	}
	if req.Dir != "" && !filepath.IsAbs(req.Dir) {
		writeRunError(w, http.StatusBadRequest, "dir must be absolute")
		return
	}
	if req.HarnessKind != "" && !harnessKindPattern.MatchString(req.HarnessKind) {
		writeRunError(w, http.StatusBadRequest, "harness_kind must match "+harnessKindPattern.String())
		return
	}
	rc := http.NewResponseController(w)
	// A child may run longer than the socket's write timeout.
	_ = rc.SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	frames := &frameWriter{enc: json.NewEncoder(w), rc: rc}
	done := d.run(r.Context(), session.FromRequest(r), req, frames)
	done.Schema = daemonStreamSchema
	_ = frames.write(runFrame{Done: &done})
}

// resolvedRef is one authorized reference waiting for its credential: the
// session's OAuth credential for provider, or the tenant-stored secret of an
// opaque_ref descriptor.
type resolvedRef struct {
	key      string
	ref      connectorCredentialRef
	provider string
	secret   *policybundle.Connector
}

func (d *Daemon) run(ctx context.Context, sessionID string, req daemonRunRequest, frames *frameWriter) runDone {
	cfg := Config{AppendAudit: d.AppendAudit, AuditCrypto: d.AuditCrypto, SessionID: sessionID}
	argv := req.Argv
	deny := func(code, reason string, exitCode int, connectorIDs, fields []string) runDone {
		appendRunAudit(io.Discard, cfg, connectorIDs, fields, argv[0], argv, code, exitCode)
		return runDone{Decision: "deny", ReasonCode: code, Reason: reason, ExitCode: exitCode}
	}

	var plain []string
	var refs []resolvedRef
	var connectorIDs, fields []string
	for _, entry := range req.Env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || key == "" {
			continue
		}
		if key == routeKeyEnv {
			// Only the daemon sets the route key; a caller's value is dropped.
			continue
		}
		ref, isRef := parseConnectorCredentialRef(value)
		if !isRef {
			plain = append(plain, entry)
			continue
		}
		connectorIDs, fields = appendUnique(connectorIDs, ref.connectorID), appendUnique(fields, ref.field)
		if req.Connector != "" && req.Connector != ref.connectorID {
			return deny("credential_reference_mismatch", "a credential reference does not match --connector", 1, connectorIDs, fields)
		}
		refs = append(refs, resolvedRef{key: key, ref: ref})
	}
	mintsRouteKey := d.RouteKeys != nil && sessionID != ""
	if len(refs) == 0 && !mintsRouteKey {
		return deny("credential_reference_missing", "run requires at least one kei://connectors/<id>/<field> environment reference", 2, nil, nil)
	}

	subject := ""
	for i := range refs {
		ref := refs[i].ref
		grant, err := d.Authorize(ctx, invoke.DaemonCall{
			Session:     sessionID,
			ConnectorID: ref.connectorID, Capability: runCapability, AgentID: req.AgentID,
			Resource: "kei://connectors/" + ref.connectorID + "/" + ref.field,
		})
		switch {
		case err != nil:
			return deny("request_canceled", "request canceled", 1, connectorIDs, fields)
		case grant.ReasonCode == invoke.ReasonSessionNotFound:
			return deny(invoke.ReasonSessionNotFound, "the session does not exist or has ended", 1, connectorIDs, fields)
		case !grant.HasSession:
			return deny("no_session", "no active session: start one with PUT /v1/session", 1, connectorIDs, fields)
		case !grant.Allow:
			return deny(grant.ReasonCode, grant.Reason, 1, connectorIDs, fields)
		case grant.Subject == "" || (subject != "" && grant.Subject != subject):
			return deny("subject_unlinked", "the session subject is not linked", 1, connectorIDs, fields)
		}
		if grant.Descriptors {
			secret, code, reason := descriptorReference(grant.Connector, ref, d.Secrets)
			if code != "" {
				return deny(code, reason, 1, connectorIDs, fields)
			}
			refs[i].secret = secret
		} else {
			switch {
			case grant.Provider == "":
				return deny("unresolved_reference", "the policy bundle does not describe this connector", 1, connectorIDs, fields)
			case !invoke.IsSessionConnector(grant.Connector):
				return deny("credential_source_not_supported", "the policy bundle does not describe this connector's credential source", 1, connectorIDs, fields)
			case !sessionCredentialFields[ref.field]:
				return deny("unresolved_reference", "a session credential provides only the token field", 1, connectorIDs, fields)
			}
		}
		subject, refs[i].provider = grant.Subject, grant.Provider
	}

	// The route key is minted last, after every reference is authorized, and
	// lives only as long as the child.
	var routeKey string
	if mintsRouteKey {
		key, err := d.RouteKeys.Mint(sessionID, req.AgentID, req.HarnessKind)
		if err != nil {
			var denied *RouteKeyDenied
			if errors.As(err, &denied) {
				return deny(denied.Code, denied.Reason, 1, connectorIDs, fields)
			}
			return deny("route_key_unavailable", "the MCP route key could not be minted", 1, connectorIDs, fields)
		}
		routeKey = key
		defer d.RouteKeys.Revoke(routeKey)
		plain = append(plain, routeKeyEnv+"="+routeKey)
	}

	var exitCode int
	var spawnErr error
	var handedOutAt time.Time
	err := d.withCredentials(ctx, sessionID, subject, refs, plain, func(env []string, secrets []string) {
		if routeKey != "" {
			secrets = append(secrets, routeKey)
		}
		handedOutAt = time.Now().UTC()
		exitCode, spawnErr = spawn(ctx, argv, env, req.Dir, frames, secrets)
	})
	if err != nil {
		code, reason, connect := invoke.CredentialDenial(err)
		done := deny(code, reason, 1, connectorIDs, fields)
		done.Connect = connect
		return done
	}
	if spawnErr != nil {
		return deny("command_not_started", "the command could not be started", exitCode, connectorIDs, fields)
	}
	// The child started with every resolved credential in its environment:
	// each connector's credential was handed out, whatever the exit code.
	d.appendCredentialAccess(handedOutAt, subject, req.AgentID, refs)
	outcome := "success"
	if exitCode != 0 {
		outcome = "failure"
	}
	appendRunAudit(io.Discard, cfg, connectorIDs, fields, argv[0], argv, outcome, exitCode)
	return runDone{Decision: "allow", ExitCode: exitCode}
}

// withCredentials enters one credential store Use per reference, so every
// resolved value is in scope while fn runs the child, and none after.
func (d *Daemon) withCredentials(ctx context.Context, sessionID, subject string, refs []resolvedRef, env []string, fn func(env, secrets []string)) error {
	var enter func(i int, env, secrets []string) error
	enter = func(i int, env, secrets []string) error {
		if i == len(refs) {
			fn(env, secrets)
			return nil
		}
		use := func(token string) error {
			return enter(i+1, append(env, refs[i].key+"="+token), append(secrets, token))
		}
		if refs[i].secret != nil {
			return invoke.UseSecret(ctx, d.Secrets, *refs[i].secret, use)
		}
		return d.UseCredential(ctx, sessionID, subject, refs[i].provider, use)
	}
	return enter(0, append([]string(nil), env...), nil)
}

// descriptorReference checks a kei://connectors reference against the
// connector's bundle descriptor (ADR-034, HAI-378). It returns the descriptor
// whose tenant-stored secret fills the reference, nil for the session's own
// OAuth credential, or a denial code and reason.
func descriptorReference(c *policybundle.Connector, ref connectorCredentialRef, secrets invoke.SecretResolver) (*policybundle.Connector, string, string) {
	if c == nil || c.ID != ref.connectorID {
		return nil, "descriptor_invalid", "the policy bundle has no descriptor for this connector"
	}
	if contract.AccountModel(c.AccountModel) == contract.AccountModelDomainDelegation {
		return nil, "account_model_not_supported", "domain-wide delegation is not executed yet"
	}
	switch contract.CredentialSource(c.CredentialSource) {
	case contract.CredentialSourceOAuth:
		if contract.AccountModel(c.AccountModel) != contract.AccountModelPerUser {
			return nil, "credential_source_not_supported", "the daemon resolves oauth connectors only with the session's own connection"
		}
		if !sessionCredentialFields[ref.field] {
			return nil, "unresolved_reference", "a session credential provides only the token field"
		}
		return nil, "", ""
	case contract.CredentialSourceOpaqueRef:
		if c.CredentialRef == "kei://connectors/"+ref.connectorID+"/"+ref.field {
			return c, "", ""
		}
		// An external credential_ref (HAI-1000, HAI-1066): the customer's own
		// secret, usable only once credential sync resolved it into the
		// index for exactly this connector and field.
		if invoke.IsExternalRef(c.CredentialRef) {
			if err := secrets.CheckExternalField(*c, ref.field); err != nil {
				code, reason, _ := invoke.CredentialDenial(err)
				return nil, code, reason
			}
			return c, "", ""
		}
		return nil, "unresolved_reference", "the reference does not name the connector's credential field"
	}
	return nil, "descriptor_invalid", "the descriptor's credential source is not supported"
}

// spawn runs argv with exactly env in dir, streaming redacted output as
// frames. A command without a slash is found on env's PATH, not the daemon's.
func spawn(ctx context.Context, argv, env []string, dir string, frames *frameWriter, secrets []string) (int, error) {
	path, err := lookPath(argv[0], env, dir)
	if err != nil {
		return 127, err
	}
	stdout := newRedactingWriter(streamWriter{frames: frames, stream: "stdout"}, secrets)
	stderr := newRedactingWriter(streamWriter{frames: frames, stream: "stderr"}, secrets)
	cmd := exec.CommandContext(ctx, path, argv[1:]...)
	cmd.Args[0] = argv[0]
	cmd.Env, cmd.Dir, cmd.Stdin, cmd.Stdout, cmd.Stderr = env, dir, nil, stdout, stderr
	cmd.WaitDelay = 5 * time.Second
	err = cmd.Run()
	_ = stdout.Close()
	_ = stderr.Close()
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal()), nil
		}
		return exitErr.ExitCode(), nil
	}
	return 127, err
}

// lookPath resolves name like a shell would for the child: a name with a
// slash is used as is (relative to dir), otherwise it is searched on the
// PATH in env.
func lookPath(name string, env []string, dir string) (string, error) {
	if strings.Contains(name, "/") {
		if !filepath.IsAbs(name) && dir != "" {
			name = filepath.Join(dir, name)
		}
		return name, executable(name)
	}
	pathEnv := ""
	for _, entry := range env {
		if v, ok := strings.CutPrefix(entry, "PATH="); ok {
			pathEnv = v
		}
	}
	for _, d := range filepath.SplitList(pathEnv) {
		if d == "" {
			d = "."
		}
		if !filepath.IsAbs(d) {
			if dir == "" {
				continue
			}
			d = filepath.Join(dir, d)
		}
		if candidate := filepath.Join(d, name); executable(candidate) == nil {
			return candidate, nil
		}
	}
	return "", exec.ErrNotFound
}

func executable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() || info.Mode()&0o111 == 0 {
		return os.ErrPermission
	}
	return nil
}

func writeRunError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"message": message, "type": "runtime_error", "code": "invalid_request"},
	})
}
