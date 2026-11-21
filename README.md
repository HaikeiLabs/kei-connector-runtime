# kei-proxy

`kei-proxy` from [Haikei Labs](https://haikeilabs.com) is the Kei runtime that runs in your own environment and puts guardrails on an agent's tool calls: it decides each call against your Kei policy, releases credentials only on allow, and ships redacted audit records.

[Docs](https://docs.haikeilabs.com) · [Discord](https://discord.gg/g6QaTYWXDa)

## Install

Binary releases are available for macOS and Linux (arm64 and amd64). The
installer downloads the matching archive and verifies its SHA-256 checksum:

```sh
export PATH="$HOME/.local/bin:$PATH"
curl -fsSL https://haikeilabs.com/install.sh | sh -s -- --proxy-only -d "$HOME/.local/bin"
```

Without `-d` it installs to `/usr/local/bin`; `-v X.Y.Z` pins a version. The
[`kei` CLI](https://github.com/HaikeiLabs/kei-cli) installer bundles
`kei-proxy` too, so if you install `kei` you already have it.

## Quick start

A *harness* is the program that runs an agent and its tool calls, such as
Claude Code, Codex, OpenCode or an Agentware agent (see the
[glossary](https://docs.haikeilabs.com/kei/reference/glossary#harness)). The
harness asks `kei-proxy serve` to decide each tool call; a deny ends that call
and carries a `hint` with the next step to take.

kei-proxy needs a runtime installation and its credential. Create both with
the `kei` CLI (`kei bot init`, then `kei bot credential`; see the
[docs](https://docs.haikeilabs.com)) and keep the credential in your secret
manager. Then:

```sh
export KEI_RUNTIME_CONTROL_PLANE_URL=https://runtime.haikeilabs.com
export KEI_RUNTIME_TOKEN=...   # from your secret manager; never commit it

# 1. Check the credential, learn the installation's scope, and fetch the policy bundle.
kei-proxy runtime bootstrap

# 2. Run the daemon your harness talks to over a local Unix socket.
kei-proxy serve

# Check daemon readiness without starting another process or contacting a provider.
kei-proxy status

# 3. In another shell: show the policy bundle version and enforcement state.
kei-proxy policy show
```

## How it fits

- **[Agentware](https://github.com/HaikeiLabs/agentware)** is the open-source
  SDK for building agents and harnesses. Its socket client talks to
  `kei-proxy serve`.
- **[kei-cli](https://github.com/HaikeiLabs/kei-cli)** is the `kei` admin CLI:
  it creates runtime installations and policies, and connects Claude Code,
  Codex, OpenCode and Pi to a runtime.
- **kei-proxy** (this repository) runs beside the harness. It evaluates policy
  locally, resolves credentials from your own secret store (AWS Secrets
  Manager, Azure Key Vault or GCP Secret Manager), and sends only decisions
  and redacted audit metadata to Kei, never credentials, prompts or tool
  payloads. After an allow, the harness gets a connector's credential for
  that call from `POST /v1/credentials:release` on the daemon socket: an
  OAuth connection from the identity service, or, for a shared `opaque_ref`
  connector such as a postgres DSN, the secret from your own store (see
  [credential release](docs/unix-socket.md#post-v1credentialsrelease-kei_credential_releaseidentity)).

## Commands

| Command | What it does |
| --- | --- |
| `serve` | Long-running daemon: sessions, local policy decisions, model profiles, audit shipping and heartbeats over a Unix socket |
| `status` | Read-only local daemon status and readiness probe; custom socket paths are redacted |
| `runtime bootstrap` \| `heartbeat` | Check the installation credential and fetch policy; report liveness |
| `policy sync` \| `show` | Fetch and persist the policy bundle; print its version and state |
| `credential sync` | Sync connector credentials into your secret store |
| `model profile` \| `profiles` \| `invoke` | Resolve the model profile assigned to the installation's agent |
| `hook` | Report-only audit hook for Claude Code, Codex, OpenCode, Cursor and Pi |
| `run` | Run a child process with connector credentials |
| `identity link` \| `status` | Link a chat-platform identity to the installation |
| `collector` | Ship pending audit records to Kei |

Run `kei-proxy <command> --help` for flags.

## Documentation

- [Architecture](docs/architecture.md): where policy is decided and enforced,
  the daemon, audit spool, secret backends, heartbeat and releases
- [Unix socket API](docs/unix-socket.md) and [sessions](docs/sessions.md)
- [Policy bundles](docs/policy-bundles.md) and [policy refresh](docs/policy-refresh.md)
- [Tool manifest v3](docs/tool-manifest-v3.md) and [v4](docs/tool-manifest-v4.md)
- [Release runbook](docs/release.md)

## Building from source

Requires Go (see `go.mod`). Every dependency is public, so builds need no
credential:

```sh
go build ./...
go vet ./...
go test ./...
go build -o kei-proxy ./cmd/kei-proxy

docker build -t kei-connector-runtime .
```

Don't add `GOPRIVATE` or credential plumbing for
[kei-connector-contracts](https://github.com/HaikeiLabs/kei-connector-contracts);
it resolves through the public module proxy and checksum database.

Running the full local stack (control plane, runtime and Open WebUI) needs a
private checkout and is maintainer-only; see
[docs/development.md](docs/development.md).

## Contributing

Questions and design discussion go on [Discord](https://discord.gg/g6QaTYWXDa);
bugs and feature requests go in GitHub issues. See
[CONTRIBUTING.md](CONTRIBUTING.md). Report security issues privately; see
[SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE).
