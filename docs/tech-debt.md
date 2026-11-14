# Tech debt

Known debt in `kei-connector-runtime`. Each item names the issue, what it
costs today, the risk if nothing changes, the options for paying it down, and
the rule to follow until then.

## Every connector adapter is compiled into kei-proxy

Tracked as HAI-320.
Raised in review of the Grafana adapter (HAI-311). **Resolved 2026-10-27
(HAI-724 slice 3):** every `internal/connector/<provider>` package, the
`httpapi` invoker, and their helpers (`input`, `skillsrepo`, `connectortest`,
and the root `internal/connector` package) are deleted from this repo; the
binary no longer carries any adapter. The record below is kept for the
measurement and because the pattern could return wherever provider execution
lands next.

### Issue

Each connector adapter (`internal/connector/<provider>`) was a Go package.
After HAI-724 removed the runtime's connector execution (`connector invoke`,
`POST /v1/connectors:invoke`, `internal/connector/invoke`'s executor wiring),
nothing imported them, and until the cleanup slice deleted them every
`kei-proxy` binary carried every adapter, whether or not a tenant used that
provider. Each new connector made the binary larger, and it also widened the
code every customer runs and has to trust.

### Measurement (2026-10-01, with the discord and grafana adapters)

- `go build -trimpath -ldflags="-s -w" ./cmd/kei-proxy`: **about 12 MB**
  (12,582,242 bytes).
- The adapters themselves are small. These are compiled symbol sizes from
  `go tool nm -size` on an unstripped build:

  | Adapter | Size |
  | --- | --- |
  | grafana | ~19 KB |
  | discord | ~12 KB |
  | crm | ~12 KB |
  | notion | ~8 KB |
  | all `internal/connector/*` packages together | ~93 KB |

- The binary is mostly shared dependencies: the Go runtime and standard
  library (`net/http`, `crypto/tls`, and so on), and the secret-store
  backends' cloud SDKs (`aws-sdk-go-v2` ~0.9 MB and the Azure SDK ~0.36 MB of
  symbols). Adapters written on `net/http` add only kilobytes each.

So at the time the cost per connector was negligible. The debt was in the
pattern, not the current size.

### Risk

- **Heavy provider SDKs.** One adapter that pulls in a vendor SDK (a cloud
  SDK, a gRPC client, a generated API client) can add megabytes and a large
  transitive dependency tree to every runtime, including runtimes that never
  use that provider.
- **Many connectors.** Community or long-tail connectors would all land in
  the one binary. That means size, build time, and supply-chain surface grow
  with the catalog rather than with what a tenant uses. Every adapter change
  also forces a runtime release.

### Options for later

These are not decided; HAI-320 owns the choice.

1. **Per-connector build tags.** Each adapter registers itself behind a
   build tag (for example `//go:build connector_grafana`), so a deployment can
   build a `kei-proxy` with only the adapters it needs. This is cheap and needs
   no new runtime machinery. The cost is a build matrix, and a choice between
   a default "all" image and per-tenant builds.
2. **Out-of-process adapters, fetched on demand.** Adapters ship as separate
   signed executables or modules that `kei-proxy` fetches and runs as needed.
   `kei-proxy` stays the credential boundary: it resolves the credential,
   decides, audits, and hands the adapter only what one call needs, then
   redacts and caps the result. This needs a process or plugin protocol,
   artifact signing, and verification.
3. **A generic, contract-driven HTTP adapter** driven by access-mode metadata
   in `kei-connector-contracts` (HAI-319). Most read connectors are "an
   authenticated GET plus a field allowlist", so they could be described as
   data and need no Go code. A bespoke adapter would remain only where the
   provider needs logic (pagination quirks, bounded queries, multi-request
   reads).
4. **CLI and MCP access through `kei-proxy run -- <cmd>`** (HAI-305). Where
   a provider already has a good native CLI or MCP server, `kei-proxy` injects
   the credential into that tool's process instead of reimplementing the API.
   The tool lives outside the binary.

These can be combined. For example, the generic adapter (3) could cover most
connectors, with build tags (1) or out-of-process adapters (2) for the rest.

### Interim rule

Moot since the resolution above: there are no adapters left in this repo to
review. Wherever provider execution lands next (HAI-320's options), carry the
rule there: no heavy SDKs in adapters, and check each new adapter's imports
before merging.
