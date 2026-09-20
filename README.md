# kei-connector-runtime

The tenant-side connector runtime. It runs inside the customer's own
environment, evaluates ABAC policy locally, enforces the allow/deny decision,
resolves credentials from tenant-owned backends, executes approved provider
operations, and emits redacted audit metadata.

Extracted from `kei` (`cmd/kei-connector-runtime`) under
[ADR-017](https://github.com/HaikeiLabs/kei/blob/main/docs/adr/017-service-repository-boundaries-and-naming.md).

## The boundary this service exists to hold

[ADR-011](https://github.com/HaikeiLabs/kei/blob/main/docs/adr/011-tenant-side-proxy-data-plane.md)
is canonical: this is the **data plane**. The policy catalog is the control
plane and is *not* the live decision point for provider calls.

- Policy is evaluated **here**, locally, against the distributed policy bundle.
  There is no synchronous round-trip to Kei on the provider hot path.
- Credentials are resolved **here**, from tenant-owned secret/OAuth backends.
- Provider payloads and results stay **here**, inside the tenant runtime.
- Only the decision and redacted audit metadata leave — digests, never content.

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

To start the runtime with the optional OpenWebUI client:

```sh
make dev-openwebui
```

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

OpenWebUI is available at `http://localhost:3000` and is configured to use
the runtime at `http://connector-runtime:8085/v1`. Set
`KEI_RUNTIME_CONTROL_PLANE_URL` and `KEI_RUNTIME_TOKEN` before starting the
stack. OpenWebUI persists its connection settings in the local
`openwebui-data` volume; remove that volume when changing its first-launch
environment configuration.

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

## Releases

Tag `proxy-v*` to publish via goreleaser to the shared S3 release bucket under
the `kei-proxy/` prefix. Manual runs require admin permission.
