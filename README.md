# kei-connector-runtime

The tenant-side connector runtime. It runs inside the customer's own
environment, evaluates ABAC policy locally, enforces the allow/deny decision,
resolves credentials from tenant-owned backends, executes approved provider
operations, and emits redacted audit metadata.

Extracted from `kei` (`cmd/kei-connector-runtime`) under
[ADR-017](https://github.com/HaikeiLabs/kei/blob/main/docs/adr/017-service-repository-boundaries-and-naming.md).

## The boundary this service exists to hold

[ADR-011](https://github.com/HaikeiLabs/kei/blob/main/docs/adr/011-tenant-side-proxy-data-plane.md)
is canonical: as the **data plane** the connector runtime authorises every
provider invocation. Authorisation *is* delegated to the remote ABAC control
plane on every call — local bundle evaluation (ADR-011 §4) is the target
architecture but is not yet implemented.

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

The `KEI_PROXY_*` environment variables are likewise an unchanged public
contract.

## Local audit spool

`authorize` appends one JSON line per decision to `KEI_PROXY_AUDIT`, and
`kei-proxy collector` ships those lines to the catalog's audit flush endpoint.
The spool is bounded (ADR-022):

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
`KEI_AGENT_ID=AGENT_ID` when an agent-specific model
profile is desired, or `KEI_INSTALLATION_ID=...` to reuse an existing
installation instead of creating another one. Set `KEI_SUBJECT` if the local
policy configuration requires a fixed development subject.

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

The initial endpoints are `GET /healthz`, `GET /readyz`, `GET /v1/models`, and
`POST /v1/chat/completions`. The models endpoint advertises the active profile
assigned to the runtime. Chat requests authenticate with the runtime token,
obtain a `model.invoke` decision from policy-catalog, and only then resolve
provider credentials and call the model endpoint. The runtime remains
independently usable without OpenWebUI.
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

## Runtime heartbeat (liveness)

`kei-proxy runtime heartbeat` reports that this runtime installation is
connected to kei-policy-catalog (`POST /api/v1/runtime/heartbeat`). It is the
runtime-to-catalog **liveness** leg; a harness-local `/healthz` or `whoami` is
readiness only. The installation, org, and workspace come only from the token
via `whoami`. The heartbeat body never carries identity, credentials, provider
payloads, or results.

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
- `--parent-stdin` exits `0` as soon as stdin reaches EOF, so a heartbeat child
  never outlives the harness that started it.

Without `--output jsonl` the legacy contract is unchanged: one identity line on
stdout, the v1 body `{"runtime_version": ...}`, and exit `1` on a failure that
a retry cannot clear.

## Releases

Tag `proxy-v*` to publish via goreleaser to the shared S3 release bucket under
the `kei-proxy/` prefix. Manual runs require admin permission.
