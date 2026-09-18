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

It was briefly private, which required a GitHub App token or PAT in CI and a
build secret in the Dockerfile. Making the contract public removed all of that:
the module resolves through the public proxy and is verified against the public
checksum database. Do not reintroduce `GOPRIVATE` or credential plumbing for
this dependency.

## Releases

Tag `proxy-v*` to publish via goreleaser to the shared S3 release bucket under
the `kei-proxy/` prefix. Manual runs require admin permission.
