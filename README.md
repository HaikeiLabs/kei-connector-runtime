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

Not a cosmetic detail. `Kei-Chat-Harness` resolves it through `KEI_PROXY_PATH`,
`kei-cli` through `exec.LookPath("kei-proxy")` with a `/tmp/kei-proxy` fallback,
and releases publish to the `kei-proxy/` S3 prefix with `install.sh`,
`latest.txt` and checksums. ADR-017 §4 makes those external contracts: the
service was renamed, the artifact was deliberately not. CI asserts the binary
name.

The `KEI_PROXY_*` environment variables are likewise an unchanged public
contract.

## Building

The connector contract is a released **private** module, so builds need
authenticated access:

```sh
export GOPRIVATE='github.com/HaikeiLabs/*'
git config --global url."https://x-access-token:${GH_TOKEN}@github.com/".insteadOf "https://github.com/"

go build ./...
go test ./...
```

Container builds take the token as a build secret, never a build arg — an arg is
recorded in the image history:

```sh
printf '%s' "$GH_TOKEN" > /tmp/ghtok
docker build --secret id=github_token,src=/tmp/ghtok -t kei-connector-runtime .
rm -f /tmp/ghtok
```

## Releases

Tag `proxy-v*` to publish via goreleaser to the shared S3 release bucket under
the `kei-proxy/` prefix. Manual runs require admin permission.
