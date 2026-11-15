# Local development (maintainers)

> **Maintainer-only.** The full local stack needs the private `kei-console`
> checkout, which runs the Kei control plane (console, policy catalog, OIDC
> bridge and PostgreSQL). Contributors without it can still build and test
> the runtime: `go build ./...`, `go vet ./...` and `go test ./...` need no
> control plane.

`kei-proxy serve` listens on TCP port `8085` by default (next to its Unix
socket) and requires the runtime installation token
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

To start the runtime with the optional Open WebUI client:

```sh
make dev-openwebui
```

To start the control plane, runtime, and Open WebUI together after provisioning
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
`host.docker.internal` is used because the runtime and Open WebUI run in Docker
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

The Open WebUI runtime uses the generic `cli` platform. The `kei-cli` binary
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

Open WebUI is available at `http://localhost:3001` by default and is configured to use
the runtime at `http://connector-runtime:8085/v1`. Set
`KEI_RUNTIME_CONTROL_PLANE_URL` and `KEI_RUNTIME_TOKEN` before starting the
stack. Open WebUI persists its connection settings in the local
`openwebui-data` volume; remove that volume when changing its first-launch
environment configuration.

The local Compose profile disables Open WebUI's own login by default
(`OPENWEBUI_AUTH=false`). This is intended only for a trusted local
development stack; the runtime token still authenticates requests from
Open WebUI to connector-runtime. Existing Open WebUI data may retain its prior
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
