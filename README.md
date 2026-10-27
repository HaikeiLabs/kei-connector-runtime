# kei-connector-runtime

The tenant-side connector runtime. It runs inside the customer's own
environment, enforces ABAC policy decisions, resolves credentials from
tenant-owned backends, executes approved provider operations, and emits
redacted audit metadata.

In the ADR-011 target architecture, the runtime hosts both a **Policy
Decision Point (PDP)** and a **Policy Enforcement Point (PEP)**: the PDP
evaluates applicable policy and returns allow or deny; the PEP intercepts every
governed tool call and enforces that result. Local PDP evaluation occurs for
every governed invocation. A denial ends that invocation; a later durable grant
may affect future calls but does not alter the current one. There is no
synchronous catalog-authorization or subject-resolution request per invocation
in this flow; identity and grant APIs are separate session-setup operations
outside the runtime daemon's invocation flow. The legacy catalog-authorize path
is described below; it is being removed as local PDP evaluation ships.

Extracted from `kei` (`cmd/kei-connector-runtime`) under
[ADR-017](https://github.com/HaikeiLabs/kei/blob/main/docs/adr/017-service-repository-boundaries-and-naming.md).

## The boundary this service exists to hold

[ADR-011](https://github.com/HaikeiLabs/kei/blob/main/docs/adr/011-tenant-side-proxy-data-plane.md)
is canonical: in the **target architecture** the connector runtime is both the
PDP and the PEP for tenant-side policy evaluation — policy is evaluated and
enforced locally on every governed call without delegating the decision to the
control plane. On the legacy catalog-authorize path (described below), the
remote catalog PDP returns the decision and the runtime acts as the PEP only.
That path is being removed.

**Legacy catalog-authorize path (being removed).** Authorisation is delegated
to the remote ABAC control plane on every call (`POST /api/v1/authorize`).
The runtime is the PEP — it intercepts the call and enforces the remote
decision — but the PDP lives in the catalog. This path is being removed as
local PDP evaluation ships; no retirement date is set.

**Target architecture (ADR-011 §4).** The PDP moves into the runtime via local
bundle evaluation. The runtime still hosts the PEP, and local PDP evaluation
occurs for every governed invocation. A denial ends that invocation; a later
durable grant may affect future calls. There is no synchronous catalog
authorisation or subject-resolution request per invocation in this flow;
identity and grant APIs remain separate session-setup operations.

**Status.** Local bundle evaluation is implemented on `main` (PRs #78, #79,
#80 merged). The `serve` daemon's Unix socket serves `POST /v1/authorize`
for local PDP evaluation and `PUT/DELETE/GET /v1/session` for session
identity. On the owner-only (0600) Unix socket, only `POST /v1/authorize`
trusts the same-UID boundary instead of requiring the runtime bearer token;
TCP does not expose this local PDP route and session/model routes still
require the token. Unauthenticated local decisions omit enrollment claim URLs.
The `kei-proxy authorize` CLI subprocess is deprecated; it evaluates the
persisted local bundle and resolves the subject online only when the tool or a
reached policy needs it (see `docs/policy-bundles.md`). It will be removed
once all harnesses have migrated to the socket path. The bundle contract is defined by
ADR-026 (G0 decisions accepted in Kei #681, #682, #693): unsigned canonical
JSON over authenticated HTTPS; no bundle signing, key distribution, or
encryption. The session subject is held in runtime memory; memberships, roles,
and grants arrive in the bundle. Identity and grant APIs remain separate
session-setup operations. Per-call approvals are removed (ADR-027, Kei #681).

**Deny-and-defer pattern.** A local PDP deny ends that invocation; the harness
does not pause, retry, or escalate the denied call. After repeated denials, a
harness may offer the user a separate way to request a durable user/group grant
from the policy catalog. That access request does not approve, pause, or replay
the denied invocation — a granted policy change reaches the runtime through the
next bundle sync and affects later invocations.

- Credentials are resolved **here**, from tenant-owned secret/OAuth backends.
- Provider payloads and results stay **here**, inside the tenant runtime.
- Only the decision and redacted audit metadata leave — digests, never content.
- Failing closed on any ABAC denial, transport error, or unresolvable target
  ensures the data-plane boundary is enforced at the delegation point.

Credential values, provider payloads, model prompts/completions and customer
documents must never be sent to the Kei control plane. The authorize response
carries no credential field, and connector invocation returns a metadata-only
signed envelope that fails closed on any non-200.

## The binary is `kei-proxy`

Not a cosmetic detail. `kei-chat-harness` resolves it through `KEI_PROXY_PATH`,
`kei-cli` through `exec.LookPath("kei-proxy")` with a `/tmp/kei-proxy` fallback,
and releases publish to the `kei-proxy/` S3 prefix with `install.sh`,
`latest.txt` and checksums. ADR-017 §4 makes those external contracts: the
service was renamed, the artifact was deliberately not. CI asserts the binary
name.

The same binary supports two modes. **CLI commands** (`authorize`,
`collector`, `credential`, `model`, `runtime`, `identity`) each perform one
governed action and exit; the `authorize`
command acts as the PEP, and the PDP runs locally in the same process.
**`kei-proxy serve`** is a long-running daemon that exposes a local HTTP/1.1
API on a Unix socket (default `/run/kei-proxy/runtime.sock`, mode `0600`) and
an optional TCP listener (`KEI_PROXY_LISTEN_ADDR`, default `:8085`). The
socket API serves health, readiness, model profile, chat-completion,
authorize, and session routes. Governed tool authorization over the socket —
the daemon-side PEP — replaces the legacy `authorize` CLI subprocess.

The `KEI_PROXY_*` environment variables are likewise an unchanged public
contract.

### Policy refresh failures

When the control plane refuses a bundle refresh (`409` not ready, `401`/`403`,
`5xx`), the runtime keeps its stored bundle, logs a warn line with
`http_status`, `reason` and `detail`, and ages the bundle until it fails
closed. [docs/policy-refresh.md](docs/policy-refresh.md) covers the log
fields, the `active` → `stale_but_valid` → `expired` states, and how to read
`policy/state.json`.

### Desktop harness resync

On a desktop install, the policy refresher inside `kei-proxy serve` and
`kei-proxy runtime heartbeat` keeps Claude Code, Codex and OpenCode native
config in line with the bundle (HAI-432). After each refresh that changes the
bundle, and on a timer, it runs `kei harness sync --check --json` (the `kei`
binary next to `kei-proxy`, then `PATH`) and runs `kei harness sync` when the
check exits 1. It logs counts only. If another writer rewrites the same
harness again within three checks, the timer doubles, up to one hour, and
`kei-proxy policy show` reports `harness_resync.state` as
`harness resync backoff`; three clean checks reset it.

- `KEI_PROXY_HARNESS_RESYNC_INTERVAL` sets the timer as a Go duration
  (default `5m`); `off` or `0` disables the loop.
- It does nothing when no `~/.claude`, `~/.codex` or OpenCode config
  directory exists (server installations), and its failures never affect
  bundle refresh or heartbeats.

### Deny hints

Every deny response — the one-shot `authorize` CLI and the socket `authorize`
route — carries a stable `hint` field
next to `reason_code`: the concrete next step a developer should take. The hint
is a pure function of `reason_code`, held in one table (`pkg/denyhint`), and is
omitted (`omitempty`) for any code outside the table rather than offering a
generic or wrong command.

| reason_code | hint |
| --- | --- |
| `agent_not_bound_to_connector` | Bind the agent to the connector on the console Connectors page (kei-cli has no bind command). |
| `no_matching_policy` | Add a policy for this source and target: `kei policies create --name <name> --src-pattern <src> --dst-pattern <dst> --effect permit` |
| `tool_not_registered` | Register the harness tools: `kei harness sync --harness custom --manifest tools.json` |
| `agent_not_assigned` | Assign an agent to this runtime installation on the console Agents page so the runtime identity has a default agent. |
| `credential_unavailable` | Connect the provider on the console Connectors page (or deliver the credential) so the runtime can resolve the connector credential. |
| `subject_missing` | Link the invoking user to this installation on the console Users page so a subject can be resolved. |

## Linking a platform identity

Harnesses can start a platform-neutral identity claim with the `identity-link`
CLI command:

```sh
kei-proxy identity link \
  --platform discord \
  --platform-user-id 705967865836339301
```

Pass `--tenant-id` for providers whose user IDs are only unique within a tenant.
The command reads `KEI_RUNTIME_TOKEN` and `KEI_RUNTIME_CONTROL_PLANE_URL` from
the environment, so the installation and workspace come from the authenticated
runtime credential. It prints JSON containing `claim_url` and `expires_at` to
stdout. The claim URL is a bearer secret; a harness must deliver it privately
to the initiating user and must not log or persist it. The default control
plane timeout is eight seconds to fit within the Python harness's subprocess
deadline.

## Runtime installation credential

Per ADR-020 and HAI-119, `KEI_RUNTIME_TOKEN` is the only supported runtime installation
credential input. Set it in the runtime environment alongside
`KEI_RUNTIME_CONTROL_PLANE_URL`. Runtime CLI commands do not accept credential
flags. The retired `--key` and `--harness-key` inputs are not supported.

### Upgrading from the in-cluster relay modes

The former in-cluster relay settings are no longer read; set
`KEI_RUNTIME_CONTROL_PLANE_URL` + `KEI_RUNTIME_TOKEN`. Every command now talks
to the control plane's `/api/v1/runtime/...` routes with the installation
credential (ADR-033: east-west `X-KEI-API-Key` stays inside the cluster). The
provisioning commands and legacy endpoint overrides are removed, as is the
OAuth bridge relay in `authorize`. See
[CHANGELOG.md](CHANGELOG.md) for the full list and replacements.

## Local audit spool

`authorize` appends one JSON line per decision to `KEI_PROXY_AUDIT`, and
`kei-proxy collector` ships those lines to the catalog's audit flush endpoint.
When `KEI_PROXY_AUDIT` is unset, `kei-proxy serve` appends local `/v1/authorize`
decisions to `$KEI_RUNTIME_STATE_DIR/audit/harness-tool.jsonl` (or the platform
default runtime state directory) and runs its in-process collector against the
same path. An explicit `KEI_PROXY_AUDIT` path overrides this default. Decision
events retain the framework, tool, and argument digest; raw command/tool input
is not recorded. The spool is bounded (ADR-022):

- **Cap.** The active file plus its sealed segments never exceed
  `KEI_PROXY_AUDIT_MAX_BYTES` (default 104857600, 100 MiB). The active file is
  sealed into `<path>.<seq>` segments at a tenth of the cap.
- **Overwrite oldest unsent.** When a decision would cross the cap, the oldest
  segments are deleted, sent or not, so the newest records are kept. The loss
  is counted in `<path>.meta` and the collector logs a warning for it.
- **Decisions reserved.** Decision and lifecycle records share the file,
  distinguished by `event_class` (absent means decision). A lifecycle record
  is refused and counted once the spool would reach 90% of the cap, so it can
  never cause a decision to be evicted. The collector never flushes a
  non-decision record as a decision; until the catalog has a lifecycle flush
  route, lifecycle records are counted and logged as skipped.

Writers, rotation, eviction, and the collector's sealing of the active file
are serialized by an `flock` on `<path>.lock`. The collector records its
position as `{segment, lines_sent}` in `<path>.state`, deletes a segment once
every line in it is acknowledged, and migrates the older `<path>.offset` line
count on first run. Flushes stay idempotent: the catalog dedupes on `span_id`.

### Harness tool audit

`kei-proxy hook <claude|codex|opencode> --harness <agent-id>` records each
harness tool call as an `event_class: "harness_tool"` line. It appends to
`KEI_PROXY_AUDIT` when set. Otherwise it appends to
`$KEI_RUNTIME_STATE_DIR/audit/harness-tool.jsonl`, using the platform default
state directory when that variable is unset. That directory is created `0700`
and the spool files `0600`. The hook never blocks the harness: it always exits
0, including when the spool cannot be written.

The hook reads one JSON object on stdin. Claude Code and Codex send their
native hook input (`session_id`, `tool_name`, `tool_use_id`, `tool_input`,
`hook_event_name`). The OpenCode plugin that `kei harness sync` installs sends
`{phase, tool_name, session_id, tool_use_id, tool_input}`, where `phase` is
`pre`, `post`, `ask` or `permission_reply`. Session lifecycle events
(`hook_event_name` `SessionStart`, `Stop` or `SessionEnd`, with `session_id`)
are accepted from Codex and OpenCode but write no tool record; `SessionEnd`
clears OpenCode's active-skill attribution for that session. Golden fixtures
for each payload are under `internal/hooks/testdata/hooks/`.

The collector sends each `harness_tool` record to two places:

- `POST /api/v1/runtime/harness-tool-events:batchCreate`, the
  skill-tool-mappings ingest. It receives only `tool`, `skill`,
  `harness_kind`, and `observed_at`. The catalog rejects a batch whole when
  one event is invalid, so the collector quarantines records it cannot
  accept rather than let them block the spool: a record with no `tool` is
  dropped before sending, and a batch answered `400`, `413` or `422` is split
  until the rejected records stand alone. The rest ship. Quarantined records
  are counted by reason code (`malformed`, `tool_missing`,
  `catalog_rejected`) in `harness_tool_quarantined` in `<path>.state` and
  logged with the catalog's error status and message, never the record.
- `POST /api/v1/runtime/audit:flush`, which writes `abac.audit_records` and
  shows in the console Audit Logs. Records follow the HP harness audit event
  contract and are built field by field: `event_class`, `harness_agent_id`,
  `harness_kind` (`claude|codex|opencode`, which the catalog maps to
  `claude_code`, `codex`, and `opencode`), `tool`, `skill?`, `phase`,
  `native_decision`, `args_digest`, `digest_key_id?`, `args_ciphertext?`,
  `recipient_key_ids?`, `harness_session_id?`, `tool_use_id?`, and
  `observed_at`. Raw tool input is never sent. `args_ciphertext` is passed
  through unchanged; Kei cannot decrypt it (ADR-030). Batches hold at most 100
  records. A record that is missing a required contract field is dropped
  rather than left to block the spool.

Both routes authenticate with `KEI_RUNTIME_TOKEN` and need
`KEI_RUNTIME_CONTROL_PLANE_URL`. Delivery is at least once. The collector
advances its `<path>.state` cursor only after every route has acknowledged a
batch. A `429` waits for `Retry-After` (capped at 5 minutes); any other error,
including other 4xx (such as `401`) and 5xx responses, keeps the spool and retries with
exponential backoff (1 second to 15 minutes, with jitter).

There are two ways to run the collector, for example from the local heartbeat
service (HAI-406). Both use the same spool default as the hook:

- **Inside the daemon:** `kei-proxy serve` runs the collector in process, as
  described under the `serve` command.
- **Standalone:** `kei-proxy collector --poll [--poll-interval 1m]` runs until
  SIGINT or SIGTERM. Run `kei-proxy collector` without `--poll` for one flush
  pass, for example from a timer or after a heartbeat. `--jsonl <path>`
  overrides the spool.

Run one collector per spool. Don't run a standalone collector next to a
`serve` daemon that already ships the same spool.

## Building

The connector contract is a released **public** module
([HaikeiLabs/kei-connector-contracts](https://github.com/HaikeiLabs/kei-connector-contracts),
Apache 2.0), so builds need no credential:

```sh
go build ./...
go test ./...

docker build -t kei-connector-runtime .
```

## Local HTTP development

The runtime can expose its OpenAI-compatible adapter with `serve`. It is
bound to port `8085` by default and requires the runtime installation token
and control-plane URL before it will report ready or accept model requests.

Run the local container with:

```sh
make dev
```

The local runtime Compose stack includes MiniStack as an AWS Secrets Manager
emulator. It is persisted in the `ministack-data` volume and the runtime uses
the normal AWS Secrets Manager backend with an opt-in endpoint override:

```sh
make dev-ministack
curl -fsS http://localhost:4566/_ministack/health
```

`make dev` starts MiniStack automatically. Use `make dev-ministack-down` to
remove only its container while preserving its state volume. The override is
local-only; production deployments continue to use AWS Secrets Manager through
workload identity. Set `MINISTACK_IMAGE` to test another pinned MiniStack
image version.

To start the runtime with the optional OpenWebUI client:

```sh
make dev-openwebui
```

To start the control plane, runtime, and OpenWebUI together after provisioning
the local installation:

```sh
make dev-local
```

This starts the runtime with a bootstrap heartbeat and then binds the pending
installation automatically. The target expects `KEI_RUNTIME_INSTALLATION_ID`
in `.runtime.env`, which is written by `make dev-provision-runtime`.

The runtime can also delegate local control-plane startup to the sibling
`kei-console` checkout:

```sh
make dev-control-plane
```

By default this runs `kei-console`'s `make dev` target, which starts the
console, policy catalog, OIDC bridge, and PostgreSQL. Override
`CONTROL_PLANE_DIR` when the checkout is elsewhere. The runtime reaches the
console's runtime proxy on port `8082` from its container:

```sh
export KEI_RUNTIME_CONTROL_PLANE_URL=http://host.docker.internal:8082
export KEI_RUNTIME_TOKEN=kh_live_...
make dev-openwebui
```

Use `http://host.docker.internal:8082` for `KEI_RUNTIME_CONTROL_PLANE_URL`.
`host.docker.internal` is used because the runtime and OpenWebUI run in Docker
while the delegated control plane is published on the host.

### Provision a local runtime token

The runtime token is a one-time credential issued for a Kei runtime
installation. First install and log in to `kei-cli` against the local console
frontend/API:

```sh
kei login --api-url http://localhost:8082
```

Create an installation through the CLI or console:

```sh
kei bot init \
  --api-url http://localhost:8082 \
  --platform cli \
  --name local-openwebui
```

The OpenWebUI runtime uses the generic `cli` platform. The `kei-cli` binary
must support `--platform cli`; if an installed release predates that option,
build a current compatible CLI checkout and select it explicitly with
`make dev-provision-runtime KEI_CLI=/path/to/kei`. For example, from a
compatible `kei-cli` checkout run `go build -o /tmp/kei .`, then use
`make dev-provision-runtime KEI_CLI=/tmp/kei`. The runtime repository does not
change the `kei-cli` release workflow.

The agent assignment is optional. Without `--agent`, the runtime uses the
organization default model profile. Provide `--agent AGENT_ID` when the local
installation should use that agent's model profile.

Copy the returned installation ID, then retrieve its runtime credential into a
mode-600 local environment file:

```sh
make dev-runtime-token KEI_INSTALLATION_ID=INSTALLATION_ID
source .runtime.env
```

Or let the runtime repository perform both steps after `kei login`:

```sh
make dev-provision-runtime
source .runtime.env
```

The combined target uses `kei bot init --platform cli` and then
`kei bot credential`. Pass
`KEI_AGENT_ID=AGENT_ID` to assign an agent to the new installation when an
agent-specific model profile is desired (this is an admin-side assignment for
`kei bot init`; the runtime and harness learn it from `whoami`, not from an
environment variable), or `KEI_INSTALLATION_ID=...` to reuse an existing
installation instead of creating another one.

The target uses `kei bot credential`, never prints the token, and writes the
control-plane URL and token to `.runtime.env`. That file is local-only and must
not be committed.

OpenWebUI is available at `http://localhost:3001` by default and is configured to use
the runtime at `http://connector-runtime:8085/v1`. Set
`KEI_RUNTIME_CONTROL_PLANE_URL` and `KEI_RUNTIME_TOKEN` before starting the
stack. OpenWebUI persists its connection settings in the local
`openwebui-data` volume; remove that volume when changing its first-launch
environment configuration.

The local Compose profile disables OpenWebUI's own login by default
(`OPENWEBUI_AUTH=false`). This is intended only for a trusted local
development stack; the runtime token still authenticates requests from
OpenWebUI to connector-runtime. Existing OpenWebUI data may retain its prior
authentication state, so recreate the local data volume if this setting does
not take effect.

The Compose targets automatically load `.runtime.env` when it exists. The
runtime container defaults to `http://host.docker.internal:8082` for its
control-plane URL; the host CLI defaults to `http://localhost:8082`. Override
either explicitly when the control plane is published elsewhere.

Or run the binary already on your `PATH`:

```sh
KEI_RUNTIME_CONTROL_PLANE_URL=https://... \
KEI_RUNTIME_TOKEN=kh_live_... \
kei-proxy serve
```

The initial endpoints are `GET /healthz`, `GET /readyz`, `GET /v1/model-config`,
`POST /v1/authorize`, and `PUT/DELETE/GET /v1/session`. The model-config
endpoint returns the runtime's assigned model profile — model name, endpoint,
and credential — as a config source for the harness. Inference **never** goes
through kei-proxy: the harness uses the returned config to call the model
provider directly. When no profile is assigned the endpoint returns
`{"status":"no_profile"}` and the harness falls back to its own configuration
(environment, config file, or Open WebUI connections). Profile assignment and
credentials are resolved entirely within the daemon; no `model.invoke` policy
decision is made. The runtime remains independently usable without Open WebUI.

### Local daemon socket

`kei-proxy serve` is a long-running local daemon. Harnesses on the same host
connect to its local HTTP/1.1 API over a Unix domain socket. Local IPC keeps
communication fast, avoids managing a local TCP port for harnesses, and uses
the operating system's socket permissions to limit access to the runtime's OS
user. The runtime and harness should run as the same OS user. HTTP bearer
authentication and model authorization still apply to requests made through
the socket. The socket serves health, readiness, model profile, and
chat-completion, authorize, and session routes; governed tool authorization
(the PEP) over the socket replaces the legacy `authorize` CLI subprocess.
Clients can register tool metadata with `POST /v1/tools:register` by sending
the tool-manifest JSON body. The daemon accepts only `kei.tool-manifest/v3`;
v1, v2, and v4 are rejected. Agentware 0.12.0 posts v3 and is unaffected.
The daemon validates it, syncs it to the catalog using its runtime credential,
and returns the catalog's added, updated,
removed, and unchanged counts. Registration requires the normal socket runtime
authentication and does not grant policy access. The daemon does not create or
modify a manifest file. With `KEI_CREDENTIAL_RELEASE=identity`, the socket
also serves `POST /v1/credentials:release`: after an allow decision, the
daemon re-runs the same decision and, only on allow, returns the session-held
connector credential value with its expiry; a deny returns a typed
`reason_code` and no credential. The value is held in session memory, flushed
when the session ends, and is never logged or printed.

The default socket is `/run/kei-proxy/runtime.sock` on Linux or
`$TMPDIR/kei-proxy/runtime.sock` on macOS (falls back to `os.TempDir()`); set
`KEI_RUNTIME_SOCKET_PATH` to use another path. The runtime creates the socket
with mode `0600` and removes it on graceful shutdown. The parent directory must
be writable by the runtime user; on Linux service installations, provision
`/run/kei-proxy` for that user. The existing TCP listener remains available
through `KEI_PROXY_LISTEN_ADDR` (default `:8085`) for the current Docker
same-container OpenWebUI setup. See [docs/unix-socket.md](docs/unix-socket.md)
for why the runtime uses a Unix socket and how to run the optional same-pod
companion container.

`serve` also owns the polling audit collector. It ships `KEI_PROXY_AUDIT`
when set, otherwise the harness-tool spool at
`$KEI_RUNTIME_STATE_DIR/audit/harness-tool.jsonl` (see
[Harness tool audit](#harness-tool-audit)). It flushes every minute while
running and makes one five-second bounded flush attempt during graceful
shutdown. Failed records remain in the spool for the next start.
The health endpoint only confirms that the listener is running. Readiness is
`503` until both `KEI_RUNTIME_TOKEN` and `KEI_RUNTIME_CONTROL_PLANE_URL` are
configured; after provisioning, verify with:

```sh
curl -fsS http://localhost:8085/healthz
curl -fsS http://localhost:8085/readyz
```

It was briefly private, which required a GitHub App token or PAT in CI and a
build secret in the Dockerfile. Making the contract public removed all of that:
the module resolves through the public proxy and is verified against the public
checksum database. Do not reintroduce `GOPRIVATE` or credential plumbing for
this dependency.

## GCP Secret Manager backend

The runtime's tenant secret store supports `gcp-secret-manager` alongside
`aws-secrets-manager` and `azure-key-vault`. A reference is the secret's
resource name, `projects/{project}/secrets/{secret}`, optionally with
`/versions/{version}`. Each delivered secret is written as a new secret
version (a rotation generation); reads return the latest version.

The backend authenticates with Application Default Credentials (workload
identity) and reads no key files. On GKE the pod's service account is used
directly; elsewhere set `GOOGLE_APPLICATION_CREDENTIALS` for local
development. The secrets must already exist in the customer's project —
creating secrets is a setup step, not something the runtime does.

Grant the workload identity, on each specific secret (the least-privilege
level both roles support):

- `roles/secretmanager.secretVersionAdder` — to write delivered versions
- `roles/secretmanager.secretAccessor` — to read them

Failures are closed and redacted: a missing secret is `secret not found`, a
missing role or unreachable GCP is `secret store unavailable` with the role
names above, and a secret value never appears in an error or log line.

## Runtime heartbeat (liveness)

A harness needs only `KEI_RUNTIME_TOKEN` (plus the control-plane URL).
Installation, org, workspace, and assigned agents all come from `whoami`; do
not add an agent-ID environment variable to a harness. A supervised harness
reads its agent from the heartbeat `identity` event below.

**Containers run only `kei-proxy serve`.** The daemon owns the heartbeat:
one supervisor runs the socket and TCP listeners, the policy refresher (which
resolves the runtime identity), the audit collector, and the control-plane
heartbeat loop under one context. If any of them fails fatally (a revoked or
rejected installation, a listener error) the others stop, the collector makes
its final flush, and `serve` exits non-zero. `serve` sends the v2 heartbeat
body every `KEI_RUNTIME_HEARTBEAT_INTERVAL` (Go duration, default `1m`) and
forwards the same allowlisted harness envelope as `--output jsonl`; an invalid
envelope value is logged and left out rather than stopping the daemon.

`serve` claims its state directory (`KEI_RUNTIME_STATE_DIR`) at startup by
taking the directory's refresher lock and holds it until it exits. Only one
process refreshes policy and ships audit for a state directory:

- `kei-proxy runtime heartbeat` started beside `serve` exits at once with
  `runtime heartbeat refused: another kei-proxy process owns the runtime state
  directory ...` (exit `1`, or `4` with a `config_invalid` terminal event under
  `--output jsonl`). It sends nothing to the control plane and starts no
  second refresher or collector.
- `serve` started while a heartbeat already owns the directory fails with
  `runtime_state_dir_unavailable` and exits `1`, instead of serving without an
  identity. Stop the heartbeat process.

`kei-proxy runtime heartbeat` remains for runtimes that do not run the
authorize socket (for example a harness that only calls the one-shot CLI).

`kei-proxy runtime heartbeat` reports that this runtime installation is
connected to kei-policy-catalog (`POST /api/v1/runtime:heartbeat`). It is the
runtime-to-catalog **liveness** leg; a harness-local `/healthz` or `whoami` is
readiness only. The installation, org, and workspace come only from the token
via `whoami`. The heartbeat body never carries identity, credentials, provider
payloads, or results.

The body may additionally carry `connector_activations`: the connector ids
whose **external** `credential_ref` credential sync actually resolved in this
runtime's state directory (the connector reference index is written only after
the secret was stored in the tenant backend and validated). Kei-managed
references (`kei://connectors/...`) never appear — a connector using one is
activated by its delivery acknowledgment instead. Ids are sent only on the
beat after they resolve, retried on the next beat if that heartbeat fails, and
not repeated once a beat carrying them succeeds; a restart may re-report an id
(already-active connectors are a no-op in the catalog). Only the connector id
is sent — never the reference or secret material.

A transient catalog failure (unreachable, timeout, 5xx) is retried once within
the tick and then the loop continues; it no longer exits the process. A `429`
stretches the next tick to its `Retry-After`, capped at five intervals. Ticks
are jittered by ±10%.

Two flags, both off by default, form the supervised contract used by the
Agentware `RuntimeLink`:

- `--output jsonl` writes one JSON event per line (`identity`, `beat` with a
  closed `outcome`, `terminal`), sends the v2 heartbeat body, and uses
  classified exit codes: `0` graceful, `1` transient, `2` contract (catalog
  `400` or a malformed `whoami`), `3` unauthorized/revoked, `4` invalid config.
  It forwards only the allowlisted harness envelope: `KEI_HARNESS_KIND`,
  `KEI_HARNESS_VERSION`, `KEI_DEPLOYMENT_ENV`, `KEI_AGENTWARE_SDK_LANG`,
  `KEI_AGENTWARE_SDK_VERSION`, and `KEI_HEARTBEAT_RUN_ID`. A malformed value
  exits `4` without echoing it.
- The `identity` event carries only what `whoami` returned for the token:
  `installation_id`, `org_id`, `workspace_id`, `platform`, `status`,
  `binding_status`, `runtime_version`, and the installation's assigned agents.
  `agent_id` is the default assignment (the `is_default` entry when whoami
  leaves `agent_id` empty) and `agents` is `[{"agent_id", "is_default"}]`.
  Both are omitted when whoami has none. If the list would push the line past
  4 KiB, `agents` is cut to fit, the default entry is always kept, and
  `"agents_truncated": true` is set. These fields are additive to the v1 event
  contract; supervisors that predate them ignore them.
- `--parent-stdin` exits `0` as soon as stdin reaches EOF, so a heartbeat child
  never outlives the harness that started it.

Without `--output jsonl` the legacy contract is unchanged: one identity line on
stdout, the v1 body `{"runtime_version": ...}`, and exit `1` on a failure that
a retry cannot clear.

## Releases

`kei-proxy` is released by `.github/workflows/release.yaml` to the shared
`kei-cli-releases` S3 bucket, under the `kei-proxy/` prefix. For the
step-by-step runbook (prerequisites, watching a run, and what to do when a run
is skipped or fails), see [docs/release.md](docs/release.md).

### How a release runs

1. **Authorize manual release.** Runs only for `workflow_dispatch`. It fails
   unless the person dispatching has `admin` on the repository (a repository
   or organization owner). It is skipped on tag pushes.
2. **Validate tag.** Requires `proxy-vMAJOR.MINOR.PATCH[-prerelease]`. It
   sets the channel: `prerelease` for `-rc.`, `-alpha.`, or `-beta.`, and
   `stable` otherwise. On a dispatch it also fails if the calculated tag
   already exists.
3. **Release.** Runs only when Validate tag succeeded. On a dispatch it first
   creates and pushes the calculated tag. It then creates a local `vX.Y.Z`
   tag for GoReleaser, which only parses `v`-prefixed semver; that tag is
   never pushed. Next it imports the GPG key, checks the runner's AWS
   identity and bucket access, and runs GoReleaser to build, sign, and
   upload. Finally it uploads `install.sh`, checks the published checksums
   and installer for leaked credentials, and, for stable releases only,
   writes `latest.txt`.

Validate tag and Release run on the self-hosted `kei-cli-release` runner,
the same one kei-cli uses. The runner Pod gets AWS access from its IRSA role,
so no AWS credentials are stored in the repository or the workflow. The
Release job runs in the `release` environment, which holds the
`GORELEASER_SIGNING_KEY` secret (the GPG key for
`kei-cli-releases@haikeilabs.com`). The environment has no required reviewers
or branch policy; the owner check lives in the workflow. The optional
repository variables `AWS_REGION` (default `us-east-1`) and
`AWS_S3_RELEASES_BUCKET` (default `kei-cli-releases`) are not set today.

### Cutting a release

**Tag push:**

```sh
git fetch origin
git tag proxy-vX.Y.Z origin/main
git push origin proxy-vX.Y.Z
```

Before #35, tag pushes silently skipped the Release job. Since #35, a tag
push releases.

**Manual dispatch** (repository or organization owners only). The workflow
bumps the highest stable `proxy-vX.Y.Z` tag, then creates and pushes the new
tag itself:

```sh
gh workflow run release.yaml -R HaikeiLabs/kei-connector-runtime -f bump=patch   # or minor, major
```

### What gets published

Artifacts land at `s3://kei-cli-releases/kei-proxy/<version>/`, where
`<version>` is the tag without `proxy-v`. The public base URL is
`https://kei-cli-releases.s3.us-east-1.amazonaws.com/kei-proxy/`.

```
kei-proxy/
  install.sh                              standalone installer; overwritten every release, no-cache
  latest.txt                              latest stable version, e.g. 0.1.11; stable releases only
  <version>/
    kei-proxy_<version>_macOS_arm64.tar.gz
    kei-proxy_<version>_macOS_x86_64.tar.gz
    kei-proxy_<version>_Linux_arm64.tar.gz
    kei-proxy_<version>_Linux_x86_64.tar.gz
    kei-proxy_<version>_checksums.txt     SHA-256 of every archive
    kei-proxy_<version>_checksums.txt.sig armored GPG signature of the checksums
```

kei-cli bundles one of these archives into each CLI release. The version it
bundles is pinned by kei-cli's `KEI_PROXY_VERSION` variable, so publishing a
proxy release does not change what `kei` installs until that pin is raised.

### Verifying a release

```sh
BASE=https://kei-cli-releases.s3.us-east-1.amazonaws.com/kei-proxy
curl -fsSL "$BASE/latest.txt"; echo              # stable releases: prints the new version
V=0.1.11
A="kei-proxy_${V}_Linux_x86_64.tar.gz"
curl -fsSLO "$BASE/$V/$A"
curl -fsSLO "$BASE/$V/kei-proxy_${V}_checksums.txt"
shasum -a 256 -c --ignore-missing "kei-proxy_${V}_checksums.txt"   # Linux: sha256sum -c --ignore-missing
```

To install the standalone binary:

```sh
curl -fsSL "https://kei-cli-releases.s3.us-east-1.amazonaws.com/kei-proxy/install.sh" \
  | AWS_S3_RELEASES_URL_BASE=https://kei-cli-releases.s3.us-east-1.amazonaws.com bash -s -- -v "$V" -d "$HOME/.local/bin"
```

The installer has no default endpoint, so `AWS_S3_RELEASES_URL_BASE` is
required. Without `-d` it installs to `/usr/local/bin`.

## Audit collector

The collector ships canonical `DecisionEvent` JSONL records in batches to
`KEI_RUNTIME_CONTROL_PLANE_URL` (override with `--control-plane-url`),
authenticated with `KEI_RUNTIME_TOKEN`, which it requires. During
the Pedro audit-spool migration it also accepts the earlier Agentware JSONL
shape, converts it to the canonical catalog record, and hashes any stored tool
arguments before upload. Both record shapes can therefore share the runtime's
single resumable spool without sending raw arguments to the control plane.

Licensed under the Apache License 2.0, see LICENSE.
