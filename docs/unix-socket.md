# Why kei-proxy serves over a Unix socket

`kei-proxy serve` exposes its HTTP/1.1 API on a Unix domain socket. The default
path depends on the operating system: `/run/kei-proxy/runtime.sock` on Linux,
`$TMPDIR/kei-proxy/runtime.sock` on macOS (falls back to `os.TempDir()`).
Override with `KEI_RUNTIME_SOCKET_PATH`. The runtime creates the socket with
mode `0600`, refuses to replace an active socket or a regular file, replaces a
stale socket left behind by a crash, and removes the socket on graceful
shutdown. Requests over the socket use the runtime bearer token except for explicitly
configured tokenless owner-session calls. `KEI_TOKENLESS_OWNER_SESSION` defaults
on for local desktop installs and off for server deployments; set it to `false`
to disable. When enabled, the mode-0600 socket binds requests that omit a
session to a named session for the v2 bundle's verified installation subject.
The tokenless routes are `POST /v1/authorize`, `/v1/preflight`, `/v1/consume`,
and `/v1/connectors:invoke`. The subject is rebound on bundle refresh and its
session is ended if the subject disappears or changes. If the current v2 bundle
does not provide a usable subject, tokenless calls fail closed with
`owner_subject_unavailable`. `PUT /v1/session` and `POST /v1/commands:run` stay
token-only; token callers remain unchanged. The TCP listener never accepts
tokenless calls. Unauthenticated authorize
responses omit enrollment claim URLs. Runtimes built before this change still
require the bearer token on `/v1/authorize` and will reject an unauthenticated
adapter request.

`GET /v1/policy-bundle/status` returns the schema and state of the locally
stored bundle (no policy contents and no control-plane request). Its response
schema is `kei.policy-bundle-status/v1`; `bundle_schema` is the stored
`kei.policy-bundle/v1` or `kei.policy-bundle/v2` value when recognized. The
reported schema remains available for invalid or expired stored bundles so
callers do not silently downgrade to a different authorization path.

For v2 bundles, named-session `POST /v1/authorize` calls evaluate local
`tool_policies` only for tools explicitly registered with a
`harness_executor` route. Pass the runtime-issued session ID in
`X-Kei-Session`. This is a decision-only path: the harness executes the tool;
no preflight handle or connector credential is returned. V1 socket behavior is
unchanged, and one-shot `kei-proxy authorize` does not authorize v2.

There are three reasons for this design.

## 1. Speed

A harness talks to the runtime frequently — readiness probes, model profile
lookups, and chat requests — so per-request latency adds up over an agent run.
Traffic on a Unix socket stays inside the kernel. There is no TCP handshake,
no loopback routing, no TLS negotiation, and no Nagle or congestion-control
behavior. Each request costs one local IPC round trip.

## 2. Simplicity

The address is just a file path, so there is no port to choose, reserve,
or collide on. The protocol is still plain HTTP/1.1, so harnesses can use any
ordinary HTTP client with a Unix-socket dialer, for example
`curl --unix-socket /run/kei-proxy/runtime.sock http://localhost/readyz`.
Nothing new needs to be framed or versioned. Startup and shutdown are also
simple: the socket appears when the runtime is ready to accept connections
and disappears when it stops.

## 3. kei-proxy is a runtime daemon

`kei-proxy serve` is a long-running daemon that exposes its HTTP/1.1 API on a
Unix domain socket. Harness processes on the same host connect to that socket
to reach the local API: health, readiness, model profile, and chat-completion
routes. The daemon hosts both the PDP and the PEP, so every governed tool
invocation is decided and enforced locally without a subprocess or a catalog
round trip. The daemon and the harness run
independently: the daemon provides the local API, the harness connects to it.

This daemon-socket model brings three benefits:

- **Nothing is exposed on the network.** Because the socket is a file on a
  local filesystem, there is no listening port to secure, no TLS certificate
  to issue or rotate, and no network policy to write.
- **Access control comes from the filesystem.** The mode (`0600`) and owner of
  the socket path decide who can connect. Only processes running as the
  runtime's OS user can open it.
- **No port management.** The address is just a file path. There is no port to
  choose, reserve, or collide on.

### API surface

The socket serves `GET /healthz`, `GET /readyz`, `GET /v1/models`,
`POST /v1/chat/completions`, `POST /v1/authorize`, and
`PUT/DELETE/GET /v1/session`. Governed tool authorization — the PEP — uses
the local PDP on the socket (PRs #78, #79, #80 merged). `POST /v1/authorize`
is the only route that does not require a bearer token on the Unix socket;
mode `0600` limits access to processes running as the proxy's OS user.
Unauthenticated responses never include enrollment claim URLs. This exception
is not enabled on TCP. The legacy `kei-proxy authorize` CLI
subprocess is deprecated; it delegates PDP to the remote catalog and is
retained for harnesses that have not yet migrated.

Both the PEP and the PDP run in the same daemon process. The PDP evaluates
policy locally from an unsigned canonical JSON bundle (ADR-026), and the PEP
enforces the result on every governed invocation without a round trip to the
catalog. The socket route proposed in the closed PR #65 was rejected because
it called the catalog authorize endpoint per request and did not authenticate
the caller.

### Sessions: many in parallel on one daemon

One daemon serves many concurrent sessions, one per agent or user (owner
decision 2026-10-06, kei-openwebui gap K10; wiki "IDN contract_change: kei-proxy
multi-session socket API (session ids)"). Each session has its own subject and
its own connector credentials, and nothing it holds is visible to another.

- **Create:** `PUT /v1/session` with
  `{"schema":"kei.session/v2","source":"discord","external_id":"..."}` (or
  `"source":"cli"`) answers `201`:

  ```json
  {"schema":"kei.session/v2","session_id":"ks_…","user_id":"u-…","status":"linked","idle_ttl_seconds":1800}
  ```

  `session_id` is opaque and unguessable (`ks_` + 32 random bytes,
  base64url), held in daemon memory only.
- **Use:** send `X-Kei-Session: <session_id>` on `POST /v1/authorize`,
  `/v1/connectors:invoke`, `/v1/commands:run`, `/v1/chat/completions` and
  `GET`/`DELETE /v1/session`. A decision uses only that session's subject and
  credentials. A header, not a body field, so one mechanism works on every
  route (the bodies reject unknown fields).
- **Fail closed:** an id that was never created, has ended or expired denies
  `session_not_found`: a `deny` decision on `/v1/authorize`, a deny on
  `connectors:invoke` and `commands:run`, `404` on `GET`/`DELETE`.
- **End:** `DELETE /v1/session` with the header ends that session and flushes
  only its credentials. A session unused for `KEI_SESSION_IDLE_TTL` (Go
  duration, default `30m`) ends too; each use restarts the clock. Policy
  refresh revokes only the sessions whose subject the bundle no longer grants;
  installation revocation revokes all of them.
- **No cap:** sessions are served concurrently with no global lock on the
  request path, so a slow call in one session never waits on another; the
  limit is the host.
- **Not bound to the connection:** HTTP clients pool and reuse socket
  connections, so the id, not the connection, names the session.
- **CLI and hooks:** `kei-proxy authorize`, `connector invoke`, `run` and
  `hook` take `--session` (default `$KEI_SESSION_ID`) and send the header.
  Audit records (decision, connector execution, command run, harness hook)
  carry `session_id`.

**Deprecated, for one release:** a `kei.session/v1` PUT (answers `204`) and
any request without `X-Kei-Session` use the single default session, exactly as
before: a v1 PUT replaces it, and it has no idle TTL. The daemon logs
`default_session_deprecated` once per route.

### Session credentials (`KEI_CREDENTIAL_RELEASE=identity`)

With `KEI_CREDENTIAL_RELEASE=identity` (default `legacy`, which changes
nothing), a linked `PUT /v1/session` makes one call to the identity service's
`POST /api/v1/connectorCredentials:resolve` (ADR-032 I11) with the runtime token
and the subject's token in `X-Kei-Subject-Token`. A tokenless owner session may
also load credentials when the fresh verified bundle contains a linked identity
for the exact installation-owner user; the daemon uses that identity's subject
token, never the installation token or caller input. Missing linked identity or
subject token means no credentials are loaded and connector use denies. The call
goes to `KEI_CREDENTIAL_RELEASE_URL`, or to the runtime control plane when that
is unset. I11 requests carry a generated `X-Request-ID`; failed-load warnings
include only the target hostname and safe request IDs for log correlation. The
client does not follow redirects, so runtime and subject credentials cannot be
forwarded to a redirect target. Credentials live only in each session's daemon-
memory store (ADR-034, owner option A). Ending a session, owner-session reconciliation on
bundle refresh, revocation, or daemon exit zeroes and drops that session's
credentials. A provider 401 triggers one single-provider re-fetch and one retry,
and after that the call is denied. The daemon sets `RLIMIT_CORE=0` so it never
core-dumps them.

**No socket route returns a credential.** Any process running as the proxy's
OS user can reach the owner-only socket. Only the explicitly configured owner
routes listed above use that same-UID boundary without a bearer token; session
creation and command execution remain token-authenticated. Credentialed work runs
inside the daemon instead, through the two routes below.

### `POST /v1/connectors:invoke` (`KEI_CREDENTIAL_RELEASE=identity`)

The daemon runs one governed connector call and returns only its result:

1. **Decide.** The local PDP decides the call with the session subject. With
   no session the call is denied `no_session`.
2. **Describe.** The daemon builds the connector's description from the
   bundle's `policy_set.connectors` entry and the installation audience.
3. **Call the provider.** The call runs with the session's held credential,
   through `credrelease.Store.Use`. A provider 401 gets the one re-fetch and
   one retry.
4. **Audit.** The execution record goes to the audit spool.

```json
{"schema":"kei.connector-invoke-request/v1","connector_id":"conn-github-0001",
 "capability":"repository.read","action":"read","resource":"repos/acme/kei",
 "input":{},"trace_id":"…","agent_id":"…"}
```

The request carries no subject and no credential. For a tokenless owner-session
call, the caller omits `session_id`; the socket middleware binds the request to
the owner session and the daemon uses that trusted session header. If a caller
includes `session_id`, it must exactly match the bound header. The answer is
`kei.connector-invoke-response/v1`, the same object `kei-proxy connector invoke`
prints. Which connectors run here depends on the bundle
(ADR-034, HAI-378 amendment):

- **The v2 bundle carries `policy_set.connectors`.** Each connector's
  non-secret descriptor decides. `oauth` with `account_model: per_user` uses
  the session's own credential. `opaque_ref` (for example an `http_api`
  connector named `crm`) reads its secret inside the daemon: the descriptor's
  `kei://connectors/<id>/<field>` reference is looked up in the connector
  reference index that `kei-proxy credential sync` writes, the index entry's
  backend must equal `credential_backend` (else
  `credential_backend_mismatch`), and the value is read from the tenant
  secret store (AWS Secrets Manager or Azure Key Vault) with the runtime's own
  cloud identity. It goes only on the provider request (for `http_api`, the
  `credential_injection` header), and a provider response that contains it
  denies `provider_error`. A routed connector without a descriptor, or one
  that fails the contract, denies `descriptor_invalid`; `domain_delegation`
  denies `account_model_not_supported`; shared `oauth` denies
  `credential_source_not_supported`; a secret that was never delivered or
  cannot be read denies `credential_unavailable`. There is no retry and no
  fallback to the catalog.
- **No `connectors` section (an older catalog).** Only providers whose
  default credential is the subject's own OAuth connection run (github,
  gmail, google_drive and linear, from the kei-connector-contracts setup
  schemas). Connectors that need config or an opaque_ref secret deny
  `credential_source_not_supported`.

In identity mode `kei-proxy connector invoke` is a
thin client of this route. It needs no control plane and holds no credential.
For v2 tool calls, `agent_id` may be omitted: the daemon uses the default
agent assigned by the authoritative runtime `whoami` identity. If no default
agent is assigned, preflight denies; the harness must not invent an agent ID.
It fails closed with `daemon_unavailable` when the daemon is unreachable, and
it rejects `--user-id`/`--provider-user`.

### `POST /v1/commands:run` (`KEI_CREDENTIAL_RELEASE=identity`)

In identity mode, `kei-proxy run [--connector <id>] -- <cmd> [args...]` is a
thin client of this route. It sends `kei.command-run-request/v1`:
`{argv, env, dir, connector, agent_id}`. `env` is its own environment, in which
`KEY=kei://connectors/<id>/<field>` values are credential references, left
unresolved. The daemon:

1. **Authorizes each reference.** The local PDP decides it with the session
   subject, as connector capability `credential` on resource
   `kei://connectors/<id>/<field>`. That's the capability and resource the
   catalog decides on the legacy path. The bundle must register a
   `credential` tool and binding for the connector, and a policy must permit
   it.
2. **Resolves each reference.** With connector descriptors in the bundle,
   an `opaque_ref` reference must equal the descriptor's `credential_ref` and
   resolves from the tenant secret store exactly as for
   `POST /v1/connectors:invoke`, with the same deny codes; a `per_user`
   `oauth` reference resolves from the session-held credential. Without
   descriptors, only the `token`/`access_token` field of a session OAuth
   provider (github, gmail, google_drive, linear) resolves; anything else
   denies.
3. **Spawns the child** with exactly the request's `env`, with the resolved
   values in place of the references. The daemon's own environment is never
   added. A bare command name is looked up on that env's `PATH`, in `dir`.
4. **Streams the result** as NDJSON frames (`kei.command-run-stream/v1`):
   `{"stream":"stdout"|"stderr","data":<base64>}`, then one
   `{"done":{"decision","reason_code","exit_code"}}`. Resolved values are
   redacted from the child's output as `[REDACTED]` before it is framed. Only
   exact matches are redacted, as on the legacy path; an encoded form of the
   value is not.
5. **Writes** a `kei.proxy-run-event/v1` audit event.

The client relays the frames to its stdout and stderr and exits with the
child's exit code: 128+N if a signal killed it, and 127 if it could not start.
A denial exits 1, or 2 when there is no reference, and the reason goes to
stderr. With no daemon, no session, a daemon in legacy mode (404) or a
rejected token, it fails closed with exit 1. The CLI process never holds a
connector credential.

**stdin is not passed through.** The child reads an empty stdin (`/dev/null`).
A command that needs input must take it from a file or argument. If the
client disconnects, the request is canceled and the child is killed.

### Same-host daemon and harness (primary deployment)

On a bare-metal or VM host, run `kei-proxy serve` as a system service. The
harness connects to the socket at the default path
`/run/kei-proxy/runtime.sock`. Both processes run under the same OS user so the
harness can open the socket.

With systemd, provision the runtime directory and user:

```ini
# /etc/systemd/system/kei-proxy.service
[Service]
User=kei-runtime
RuntimeDirectory=kei-proxy
ExecStart=/usr/local/bin/kei-proxy serve
Environment=KEI_RUNTIME_TOKEN=kh_live_...
Environment=KEI_RUNTIME_CONTROL_PLANE_URL=https://...
```

The service manager creates `/run/kei-proxy` owned by `kei-runtime` and removes
it when the service stops. The harness process, also running as `kei-runtime`,
opens the socket directly.

### Docker same-container deployment

When the harness and runtime share a container image, run `kei-proxy serve` as a
background process (e.g., a supervisor or an init script) and have the harness
connect over the socket at the agreed path. The socket lives on the container's
own filesystem so no volume mount is needed.

Run only `kei-proxy serve`. It sends the control-plane heartbeat itself and is
the one process that runs the policy refresher and audit collector for its
state directory, so do not also start `kei-proxy runtime heartbeat` or
`kei-proxy collector --poll` in the container. A `runtime heartbeat` started
beside `serve` refuses to run; a `serve` started after a heartbeat already owns
the state directory exits non-zero. See "Runtime heartbeat" in the README.

For the existing OpenWebUI deployment the runtime also keeps its TCP listener on
`KEI_PROXY_LISTEN_ADDR` (default `:8085`). OpenWebUI continues to reach the
runtime at `http://connector-runtime:8085/v1` as before.

### Optional: companion container in Kubernetes

In Kubernetes you can run the runtime as a companion container in the same pod
as the harness, sharing a socket volume. This topology is optional and
functionally identical to the same-host model above.

```yaml
spec:
  securityContext:
    runAsUser: 10001
    runAsGroup: 10001
  volumes:
    - name: kei-proxy-run
      emptyDir:
        medium: Memory
  containers:
    - name: harness
      image: example/harness
      env:
        - name: KEI_RUNTIME_SOCKET_PATH
          value: /run/kei-proxy/runtime.sock
      volumeMounts:
        - name: kei-proxy-run
          mountPath: /run/kei-proxy
    - name: kei-proxy
      image: kei-connector-runtime
      args: ["serve"]
      env:
        - name: KEI_RUNTIME_TOKEN
          valueFrom:
            secretKeyRef: {name: kei-runtime, key: token}
      volumeMounts:
        - name: kei-proxy-run
          mountPath: /run/kei-proxy
```

Mount an `emptyDir` volume at `/run/kei-proxy` in both containers and run both
with the same UID (the socket is owner-only). The harness finds its runtime at
the fixed path without service discovery. For Cloud Run multi-container
services, declare an in-memory volume and mount it at `/run/kei-proxy` in the
ingress (harness) container and in the kei-proxy companion.

### Harness client example (Go)

The socket carries the same HTTP API as TCP. Configure the harness's existing
HTTP client with a Unix-socket transport and keep using the usual HTTP URL
(the hostname is ignored by the dialer):

```go
socketPath := "/run/kei-proxy/runtime.sock"
transport := &http.Transport{
    DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
        return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
    },
}
client := &http.Client{Transport: transport}
req, err := http.NewRequestWithContext(ctx, http.MethodGet,
    "http://localhost/readyz", nil)
```

For model, session, and other authenticated routes, add the runtime token using
the same bearer-auth mechanism as the TCP client. Do not put the token in the
URL or log it. Do not pass the runtime token to a harness solely for
`POST /v1/authorize`; the owner-only socket is the caller boundary for that
policy-only route.

### Rollout checklist

1. Deploy the runtime version that supports the socket. `serve` creates the
   socket and continues to provide the TCP listener for compatibility.
2. Make the socket directory writable by the runtime user. For a host service,
   provision `/run/kei-proxy` for that user. For a companion container in
   Kubernetes, mount a shared `emptyDir` volume at `/run/kei-proxy` in both
   containers and run them with the same UID.
3. Update the harness client to dial `KEI_RUNTIME_SOCKET_PATH` (default
   `/run/kei-proxy/runtime.sock`) and confirm `GET /readyz` succeeds through
   that client. Keep bearer authentication for model and session routes; the
   local `POST /v1/authorize` route is the sole socket-only exception.
4. Keep Docker/OpenWebUI clients on `http://connector-runtime:8085/v1` during
   rollout. Once a deployment no longer needs TCP, bind it to loopback with
   `KEI_PROXY_LISTEN_ADDR=127.0.0.1:8085` and avoid publishing the port.
5. Confirm runtime logs contain `runtime_unix_listener_started` with the
   expected path and mode. A stale socket file left by a crash is replaced
   automatically. An active socket at the path (another runtime is serving),
   a regular file at the path, or a socket directory the runtime user cannot
   write is reported as `runtime_unix_listener_failed` and prevents startup.

## The TCP listener

`serve` still opens the TCP listener on `KEI_PROXY_LISTEN_ADDR` (default
`:8085`) for the existing Docker same-container OpenWebUI deployment. Harness
deployments that use the socket should not publish this port. To disable
external TCP access, bind the listener to loopback with
`KEI_PROXY_LISTEN_ADDR=127.0.0.1:8085`.
