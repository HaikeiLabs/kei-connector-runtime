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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/auditcrypto"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/invoke"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/credentials"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/secrets"
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
	// UseCredential runs fn with the session credential subject holds for
	// provider (credrelease.Store.Use).
	UseCredential func(ctx context.Context, subject, provider string, fn func(token string) error) error
	AppendAudit   func([]byte) error
	AuditCrypto   *auditcrypto.Provider
	// Store and StateDir resolve an opaque_ref connector's reference from
	// the delivered connector secret, as the legacy path does: the
	// credential-sync index in StateDir names the secret, which must match
	// the connector descriptor, and Store reads it.
	Store    secrets.Store
	StateDir string
}

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
	rc := http.NewResponseController(w)
	// A child may run longer than the socket's write timeout.
	_ = rc.SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	frames := &frameWriter{enc: json.NewEncoder(w), rc: rc}
	done := d.run(r.Context(), req, frames)
	done.Schema = daemonStreamSchema
	_ = frames.write(runFrame{Done: &done})
}

// resolvedRef is one authorized reference waiting for its credential: the
// session credential for provider, or value already read from the secret
// store for an opaque_ref connector.
type resolvedRef struct {
	key      string
	ref      connectorCredentialRef
	provider string
	value    string
}

func (d *Daemon) run(ctx context.Context, req daemonRunRequest, frames *frameWriter) runDone {
	cfg := Config{AppendAudit: d.AppendAudit, AuditCrypto: d.AuditCrypto}
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
	if len(refs) == 0 {
		return deny("credential_reference_missing", "run requires at least one kei://connectors/<id>/<field> environment reference", 2, nil, nil)
	}

	subject := ""
	for i := range refs {
		ref := refs[i].ref
		grant, err := d.Authorize(ctx, invoke.DaemonCall{
			ConnectorID: ref.connectorID, Capability: runCapability, AgentID: req.AgentID,
			Resource: "kei://connectors/" + ref.connectorID + "/" + ref.field,
		})
		switch {
		case err != nil:
			return deny("request_canceled", "request canceled", 1, connectorIDs, fields)
		case !grant.HasSession:
			return deny("no_session", "no active session: start one with PUT /v1/session", 1, connectorIDs, fields)
		case !grant.Allow:
			return deny(grant.ReasonCode, grant.Reason, 1, connectorIDs, fields)
		case grant.Subject == "" || (subject != "" && grant.Subject != subject):
			return deny("subject_unlinked", "the session subject is not linked", 1, connectorIDs, fields)
		case grant.Provider == "":
			return deny("unresolved_reference", "the policy bundle does not describe this connector", 1, connectorIDs, fields)
		}
		value, code, reason := d.resolveRef(ctx, grant, ref)
		if code != "" {
			return deny(code, reason, 1, connectorIDs, fields)
		}
		subject, refs[i].provider, refs[i].value = grant.Subject, grant.Provider, value
	}

	var exitCode int
	var spawnErr error
	err := d.withCredentials(ctx, subject, refs, plain, func(env []string, secrets []string) {
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
	outcome := "success"
	if exitCode != 0 {
		outcome = "failure"
	}
	appendRunAudit(io.Discard, cfg, connectorIDs, fields, argv[0], argv, outcome, exitCode)
	return runDone{Decision: "allow", ExitCode: exitCode}
}

// resolveRef decides how an authorized reference resolves. With a connector
// descriptor in the bundle, an opaque_ref connector's reference is read now
// from the delivered secret (the returned value), and an OAuth connector's
// must be the session subject's own connection. Without one, only a session
// OAuth provider qualifies. A session reference returns "" and is resolved
// later inside the credential store's Use. A non-empty code denies.
func (d *Daemon) resolveRef(ctx context.Context, grant invoke.Grant, ref connectorCredentialRef) (value, code, reason string) {
	if len(grant.Descriptor) == 0 {
		switch {
		case !invoke.IsSessionProvider(grant.Provider):
			return "", "credential_source_not_supported", "the daemon resolves only the session's own OAuth connections"
		case !sessionCredentialFields[ref.field]:
			return "", "unresolved_reference", "a session credential provides only the token field"
		}
		return "", "", ""
	}
	var desc invoke.Descriptor
	if err := json.Unmarshal(grant.Descriptor, &desc); err != nil {
		return "", "unresolved_reference", "the connector descriptor is malformed"
	}
	meta := desc.Metadata
	if meta.ID != ref.connectorID || meta.TenantID != grant.TenantID || meta.WorkspaceID != grant.WorkspaceID || string(meta.Provider) != grant.Provider {
		return "", "unresolved_reference", "the connector descriptor does not match the bundle"
	}
	switch meta.EffectiveCredentialSource() {
	case contract.CredentialSourceOAuth:
		switch {
		case meta.AccountModel != contract.AccountModelPerUser && (meta.AccountModel != "" || meta.Subject != grant.Subject):
			return "", "credential_source_not_supported", "shared OAuth connections are not released to a session"
		case !sessionCredentialFields[ref.field]:
			return "", "unresolved_reference", "a session credential provides only the token field"
		}
		return "", "", ""
	case contract.CredentialSourceOpaqueRef:
		if d.Store == nil || d.StateDir == "" {
			return "", "unresolved_reference", "no connector secret store is configured"
		}
		entry, err := credentials.ReadConnectorReference(filepath.Join(d.StateDir, "connector-credentials.json"), ref.connectorID, ref.field)
		if err != nil || entry.SecretBackend != desc.CredentialBackend || entry.SecretRef != desc.CredentialSecretRef ||
			meta.CredentialRef == "" || !strings.HasSuffix(entry.SecretRef, "/"+meta.CredentialRef) {
			return "", "unresolved_reference", "no delivered secret matches the connector descriptor"
		}
		secret, err := d.Store.Get(ctx, entry.SecretBackend, entry.SecretRef)
		if err != nil || secret == nil || *secret == "" {
			return "", "unresolved_reference", "the connector secret is not available"
		}
		return *secret, "", ""
	}
	return "", "unresolved_reference", "unknown credential source"
}

// withCredentials enters one credential store Use per session reference, so
// every resolved value is in scope while fn runs the child, and none after.
// A reference already read from the secret store is added directly.
func (d *Daemon) withCredentials(ctx context.Context, subject string, refs []resolvedRef, env []string, fn func(env, secrets []string)) error {
	var enter func(i int, env, secrets []string) error
	enter = func(i int, env, secrets []string) error {
		if i == len(refs) {
			fn(env, secrets)
			return nil
		}
		if refs[i].value != "" {
			return enter(i+1, append(env, refs[i].key+"="+refs[i].value), append(secrets, refs[i].value))
		}
		return d.UseCredential(ctx, subject, refs[i].provider, func(token string) error {
			return enter(i+1, append(env, refs[i].key+"="+token), append(secrets, token))
		})
	}
	return enter(0, append([]string(nil), env...), nil)
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
