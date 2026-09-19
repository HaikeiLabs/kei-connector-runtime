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
`kei-policy-catalog` checkout:

```sh
make dev-control-plane
```

By default this runs `kei-policy-catalog`'s `make dev` target and serves the
policy catalog on `http://localhost:8080`. Override `CONTROL_PLANE_DIR` when
the checkout is elsewhere. In a second terminal, point the runtime at it:

```sh
export KEI_RUNTIME_CONTROL_PLANE_URL=http://host.docker.internal:8080
export KEI_RUNTIME_TOKEN=kh_live_...
make dev-openwebui
```

`host.docker.internal` is used because the runtime and OpenWebUI run in Docker
while the delegated control plane's port is published on the host.

OpenWebUI is available at `http://localhost:3000` and is configured to use
the runtime at `http://connector-runtime:8085/v1`. Set
`KEI_RUNTIME_CONTROL_PLANE_URL` and `KEI_RUNTIME_TOKEN` before starting the
stack. OpenWebUI persists its connection settings in the local
`openwebui-data` volume; remove that volume when changing its first-launch
environment configuration.

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
provider credentials and call the model endpoint. OpenWebUI configuration and
a bundled local OpenWebUI service will be added separately; the runtime
remains independently usable without that client.

It was briefly private, which required a GitHub App token or PAT in CI and a
build secret in the Dockerfile. Making the contract public removed all of that:
the module resolves through the public proxy and is verified against the public
checksum database. Do not reintroduce `GOPRIVATE` or credential plumbing for
this dependency.

## Releases

Tag `proxy-v*` to publish via goreleaser to the shared S3 release bucket under
the `kei-proxy/` prefix. Manual runs require admin permission.
