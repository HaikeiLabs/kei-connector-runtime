# Changelog

## Unreleased

### Added: contracts v1 tool definitions at registration (HAI-849)

`POST /v1/tools:register` and the manifest loader accept contracts
`kei.tool-definition/v1` definitions in a `kei.tool-manifest/v1` envelope,
while continuing to accept manifest v2, v3, and v4. Agentware's compatibility
table should use kei-proxy **v0.3.5+** as the minimum version for v1.

### Added: live access grants in the v2 policy bundle (HAI-617)

A v2 policy bundle may carry a top-level `access_grants` array: the
workspace's live JIT access grants (ADR-038 §2). Each entry names the
principal the grant is for, the typed target it opens and when it ends.

The runtime decides a governed call as before: a rule that matches decides
it, and a matching deny always wins. Where no rule covers the call, a live
access grant opens it; a grant that has ended denies with
`access_grant_expired`, and a bundle whose grants cover nothing denies with
`no_grant_matched`. The groups a decision matches on are the ones the
verified bundle holds for that user, never the ones a session claims.

The v2 contract schema accepts the field from this release on. The catalog
projects the grants (kei-policy-catalog#363) and the shared policy package
decides them (kei-connector-contracts#38).

### Fixed

- `collector` sends decision audit batches to the canonical
  `/api/v1/runtime/audit:flush` route. Catalog skipped records count as
  acknowledged; count mismatches fail the batch for retry (HAI-436).

### Removed: in-cluster relay credential modes (GW Phase 5, ADR-033)

`ABAC_URL`, `ABAC_API_SECRET` and `OIDC_BRIDGE_SECRET` are no longer read; set
`KEI_RUNTIME_CONTROL_PLANE_URL` + `KEI_RUNTIME_TOKEN`.

East-west `X-KEI-API-Key` authentication stays inside the Kei cluster. A
runtime, in-cluster or external, authenticates only with its installation
credential through the gateway. `OIDC_BRIDGE_URL` is no longer read either.

Removed environment variables:

| Variable | Replacement |
| --- | --- |
| `ABAC_URL` | `KEI_RUNTIME_CONTROL_PLANE_URL` |
| `ABAC_API_SECRET` | `KEI_RUNTIME_TOKEN` (no service secret on the runtime) |
| `OIDC_BRIDGE_SECRET`, `OIDC_BRIDGE_URL` | none on the runtime: the catalog fetches OAuth tokens (see below) |

Removed commands and flags:

| Removed | Replacement |
| --- | --- |
| `kei-proxy init --member/--agent` (needed `ABAC_API_SECRET`) | Kei console or Kei API. This is platform provisioning, not runtime work |
| `kei-proxy org --list/--add/--remove/--update` | Kei console or Kei API (org admin) |
| `collector --abac-url` | `collector --control-plane-url` (defaults to `KEI_RUNTIME_CONTROL_PLANE_URL`) |
| `connector invoke --abac-url` | removed; no alias |
| `--abac-url` on the unwired `roles` / `role-request` code | deleted (was not reachable from the CLI) |

Behaviour changes:

- `collector` requires `KEI_RUNTIME_TOKEN`. The non-runtime
  `POST /api/v1/audit/flush` + `X-KEI-API-Key` path is gone. Every flush goes to
  `/api/v1/runtime/audit:flush` with the installation credential. Decision
  audit batches advance when the catalog's upserted and skipped counts add up
  to the received count; skipped records are logged.
- `authorize` no longer fetches OAuth tokens from the OIDC bridge relay
  (`OIDC_BRIDGE_URL` + `OIDC_BRIDGE_SECRET`). A tool service's credential
  comes only from its credential binding
  (`/api/v1/runtime/credential-bindings/...`). For OAuth connectors, use
  `kei-proxy connector invoke`: the catalog fetches the token per call
  (ADR-020, `docs/connector-execution-contract.md`).
- `authorize` and `serve` always resolve subjects at
  `KEI_RUNTIME_CONTROL_PLANE_URL` (`/api/v1/runtime/subject-attributes:resolve`).
  A leftover `ABAC_URL` is ignored.
- `kei-proxy run` (legacy credential release) authorizes through
  `KEI_RUNTIME_CONTROL_PLANE_URL`'s `/api/v1/data-connectors/invoke`. It used to
  post to `ABAC_URL`, which defaulted to `http://localhost:8080` even for
  runtime-token deployments.
- `kei-proxy model invoke` selects the profile from
  `/api/v1/runtime/model-profiles/assigned` (the installation's default-agent
  assignment). It no longer uses the internal `harness-identity` lookup.
- The connector invoke client never sends `X-KEI-API-Key`.

Before upgrading, remove `ABAC_URL`, `ABAC_API_SECRET`, `OIDC_BRIDGE_URL` and
`OIDC_BRIDGE_SECRET` from runtime deployments. Make sure each runtime,
including a standalone `collector`, has `KEI_RUNTIME_TOKEN` and
`KEI_RUNTIME_CONTROL_PLANE_URL`.
