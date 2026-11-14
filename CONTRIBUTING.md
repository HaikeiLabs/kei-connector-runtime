# Contributing to kei-proxy

kei-proxy is the Kei runtime that runs beside an agent harness and puts
guardrails on its tool calls. It is a single Go module; the binary's entry
point is `cmd/kei-proxy`. See [docs/architecture.md](docs/architecture.md) for
how the pieces fit.

## Where to coordinate

Contribution work is coordinated on
[Discord](https://discord.gg/g6QaTYWXDa). Say what you plan to work on
there before a large change, and discuss design questions there. Bugs and
feature requests go in GitHub issues; changes go in pull requests.

Report security issues privately, never in a public issue. See
[SECURITY.md](SECURITY.md).

## Development setup

You need the Go version named in `go.mod`. Every dependency is public,
including [kei-connector-contracts](https://github.com/HaikeiLabs/kei-connector-contracts),
so no credential or `GOPRIVATE` setting is needed.

```bash
go build ./...
go build -o kei-proxy ./cmd/kei-proxy
./kei-proxy --help
```

The tests run without a Kei control plane. The full local stack (console,
policy catalog and Open WebUI) needs a private checkout and is
maintainer-only; see [docs/development.md](docs/development.md).

## Validation commands

CI runs these on every pull request. Run them before you open one:

```bash
gofmt -l .                      # must print nothing
go build ./...
go vet ./...
go test -count=1 -race ./...
```

CI also checks that:

- the binary is still named `kei-proxy`; harnesses and the `kei` CLI find it by
  that name;
- no tracked file is larger than 2 MB;
- production code has no route that writes policies or groups and no default
  `permit`. The runtime decides; it never edits policy.

## Making a change

- Write the test first. Table-driven tests are the norm; follow the style of
  the file you extend.
- Keep a pull request to one change. Split refactors from behavior changes.
- Fail closed. A missing credential, an unreadable bundle or an unknown
  input must end in a deny or an error, never an allow.
- Never log or print a credential, token, prompt, tool argument or provider
  payload. Audit records carry digests, not content.
- Update the docs in the same pull request when you change a command, flag,
  environment variable, socket route or exit code: the README command table,
  `kei-proxy --help`, and the matching page under `docs/`.
- Add a line to [CHANGELOG.md](CHANGELOG.md) for any user-visible change.

## Pull request checklist

- [ ] Tests cover the new behavior, including the failure path.
- [ ] `gofmt`, `go build`, `go vet` and `go test -race` pass.
- [ ] Docs and `--help` text match the behavior.
- [ ] No secrets, internal hostnames or customer data in code, tests or
      commit messages.

## Releasing

Releases are cut by maintainers. A `proxy-vX.Y.Z` tag runs the release
workflow, which builds, signs and publishes the archives. The runbook is
[docs/release.md](docs/release.md).

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
