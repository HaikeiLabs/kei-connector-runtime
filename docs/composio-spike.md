# Composio connector spike (HAI-142): NOT FOR MERGE

This is a spike. `internal/composio` is a prototype of a `composio` connector class labelled
**third-party-managed credentials**. Kei authorizes and audits every call, and Composio
executes a tool only after an allow. Nothing wires it into `kei-proxy`, and all tests use
HTTP fixtures (no Composio account, no live key).

## Shape

- `GovernedInvoke(ctx, Authorizer, Executor, Invocation)` is the only entry point.
  The call order is:
  1. The connector must be enabled. It is off by default.
  2. The input must be a JSON object of at most 16 KiB. It is canonicalized and hashed
     before any I/O.
  3. Kei decides from an `AuthorizeRequest` that carries `input_digest`, never the input
     (execution contract §2). Only `allow` proceeds; an error or any other decision is a
     deny.
  4. The capability must be on the local allow-list.
  5. The action must match the configured action.
  6. Non-read actions need an approval id.
  7. The Kei subject maps to a Composio `user_id`, with no fallback.
  8. The project API key is resolved from an opaque secret-manager ref.
  9. One `POST /api/v3.1/tools/execute/{slug}` with a pinned version, no retries, and no
     redirects.
  10. The response is size-capped.
  11. Configured JSON fields are redacted.
- Capability names are `composio.<toolkit>.<action>`. For example,
  `GITHUB_GET_A_REPOSITORY` becomes `composio.github.get_a_repository`.
- The audit record carries `input_digest`, `result_digest`, `result_bytes`,
  `composio_log_id`, and `credential_class: third-party-managed`. It never carries the key,
  its ref, raw arguments, or result data.
- `ReasonCode(err)` maps errors onto the reason codes of the connector execution contract
  (`docs/connector-execution-contract.md`, status Proposed). Composio 404 maps to
  `provider_not_found`, and an unmapped subject maps to `oauth_not_connected`.

## Why it is not production-ready

In Composio Cloud, Composio holds the provider OAuth tokens, and tool arguments and results
transit it (logged for up to a year by default). This breaks ADR-011's rule that
credentials come from tenant-owned backends and results stay in the tenant runtime. See the
spike report for the full assessment, recommendation (go for local only), and conditions.

## Run

```sh
go test -count=1 -race ./internal/composio/ -run . -v
go test -count=1 -run TestComposioSpikeUsesSharedSecretPath .
```
