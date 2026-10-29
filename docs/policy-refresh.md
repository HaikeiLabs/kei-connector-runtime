# Policy bundle refresh and refresh failures

`kei-proxy serve` and `kei-proxy runtime heartbeat` run a policy refresher.
It fetches `GET /api/v1/runtime/policy-bundles/current` from the control plane
and keeps the bundle in `KEI_RUNTIME_STATE_DIR/policy/` current. This page
explains what the runtime does when a refresh fails, what it logs, how the
stored bundle ages, and how to read `policy/state.json`. For bundle
validation and evaluation, see [policy-bundles.md](policy-bundles.md).

## What the runtime requests

Every fetch sends `Accept: application/vnd.kei.policy-bundle.v2+json`. The
runtime no longer asks for v1, and there is no opt-in variable. When the
runtime holds an active bundle it also sends `If-None-Match` with the
bundle's digest. `serve`, `runtime heartbeat`, `runtime bootstrap` and
`policy sync` all fetch this way. A v1 bundle already on disk is still
validated and enforced until it is replaced or expires.

The refresher polls at the bundle's `refresh.poll_interval_seconds` (the
catalog sends 60), clamped to 30–300 seconds with ±10% jitter. When no bundle
is active it polls every 60 seconds. It does not read `Retry-After`.

## Responses

| Response | What the runtime does | Log line (warn) |
|---|---|---|
| `200` | Validates the candidate (ETag digest, content type, schema, audience, version) and activates it. A rejected candidate never replaces the active bundle. | None on success |
| `304` | Confirms the ETag and version header against the active bundle, then records a successful refresh (`last_success`). | None |
| `409` | Records a failed check (`reason_code: refresh_failed`). The stored bundle is kept and nothing else changes. | `policy bundle not ready (409); the active bundle stays until it expires`, on every poll |
| `401`, `403` | Records a failed check. The stored bundle is kept and the error goes to the refresher. | `policy bundle authorization denied`, then the refresher's failure line |
| Other status (for example `5xx`) | Records a failed check. The stored bundle is kept. | `policy bundle fetch failed`, then the refresher's failure line |
| Network or TLS error | Records a failed check. The stored bundle is kept. | The refresher's failure line only |

A `401` or `403` from the bundle endpoint alone does not revoke the runtime.
Revocation comes from the identity (`whoami`) or heartbeat call receiving
`401`/`403`. That sets the state to `revoked`, deletes `bundle.json`, and
denies every call with `installation_revoked`.

### Log fields

The `409`, `401`/`403` and other-status lines carry:

| Field | Value |
|---|---|
| `http_status` | The response status. |
| `reason` | The response's `reason` (for a `409`, always `policy_bundle_not_ready`). Omitted when empty. |
| `detail` | The response's `detail`, capped at 256 characters with `...` appended. If the body is not JSON, the raw body text with newlines removed is used. Omitted when empty. |
| `bundle_version_requested` | Always `v2`. |

The runtime reads at most 4 KiB of an error body. The catalog's `409`
`subject` field is not logged.

The refresher's own line, `policy bundle refresh failed; the active bundle
stays until it expires`, carries `error`, the fields above when they are
available, and `state_transition` (`<before>-><after>`) when the stored
state changed during the attempt. It is rate limited: it is logged on the
first failure, on any state transition, and then on every 10th consecutive
failed poll. A successful poll resets the count.

A `409` is not rate limited. The refresher counts it as a completed poll,
so its warn line appears on every poll, about once a minute.

### Why the catalog returns 409

`detail` names the condition. The catalog documents each one with its
operator fix in
[When the bundle is not ready (409)](https://github.com/HaikeiLabs/kei-policy-catalog/blob/main/docs/policy-bundle-issuer.md#when-the-bundle-is-not-ready-409).

| `detail` | Meaning |
|---|---|
| `no_assigned_agents` | The runtime installation has no assigned agents. |
| `group_edge_out_of_scope` | A workspace group contains a group from another organization or workspace. |
| `typed_tool_route_invalid` | A routed tool registration has unreadable route or resource-type metadata. |
| `typed_tool_route_missing` | A routed tool registration has a null route. |
| `v2_tool_catalog_not_ready` | A tool registration fails v2 route validation. |
| `v2_policy_not_ready` | A policy in scope cannot be compiled into a v2 check. |
| `binding_projection_incomplete` | A tool, connector or binding was left out of the bindings projection. |
| `identity_snapshot_not_ready` | The catalog could not build the subject snapshot from the identity service. |

## How the stored bundle ages

A failed refresh never replaces or deletes the active bundle. The bundle
ages on its own clock:

- **`active`:** the bundle validates and the last successful refresh is no
  older than `refresh.stale_after_seconds` (the catalog sends 300).
- **`stale_but_valid`:** for a v1 bundle, the last successful refresh is
  older than `stale_after_seconds`. The bundle is still enforced. For a v2
  bundle, the subject snapshot is stale: more than
  `subject_resolution.max_cache_seconds` (at most 60) has passed since
  `issued_at`. The runtime then denies (see below).
- **`expired`:** the time is at or past `not_after` (`expires_at` in
  `state.json`). The state stays `expired` until a new bundle is activated.

Other states: `cold` (no bundle yet), `invalid` (the stored bundle failed
revalidation), `unsupported` (unsupported schema) and `revoked`.

### What a v2 runtime does during a 409

A v2 bundle carries a subject snapshot that is only trusted for
`max_cache_seconds` after `issued_at`, which is at most 60 seconds. The
catalog reissues on most polls to keep it fresh. When refreshes return `409`,
nothing renews it, so about a minute after the last good bundle was issued:

- the state becomes `stale_but_valid`;
- `serve` denies authorize calls with `reason_code: subject_snapshot_stale`
  and `deny_source: runtime_state`;
- linked sessions are revoked.

So a v2 runtime fails closed within about a minute of a sustained `409`, not
at `not_after`. It recovers on the first successful refresh. A v1 bundle on
disk keeps being enforced as `stale_but_valid` until `not_after`.

One-shot `kei-proxy authorize` does not evaluate v2 bundles itself. With a v2
bundle stored it asks the running `kei-proxy serve` to decide (pass
`--session` or set `KEI_SESSION_ID`) and exits `2` when no daemon answers.

### Expiry fails closed

At `not_after`, every decision path denies with `reason_code:
policy_bundle_expired` and `deny_source: runtime_state` (one-shot
`authorize` returns the same reason code). There is no fallback to an older
bundle and no built-in allow. A missing, invalid, unsupported or revoked
bundle denies the same way, with `policy_bundle_missing`,
`policy_bundle_invalid`, `policy_bundle_unsupported` or
`installation_revoked`.

## Reading `state.json`

`state.json` lives in the `policy/` directory of `KEI_RUNTIME_STATE_DIR`. On
macOS that is `~/Library/Application Support/kei-proxy/policy/state.json`;
see the README for the Linux defaults. The file is mode `0600` and holds
metadata only. The bundle itself is `bundle.json` next to it.

```json
{
  "highest_bundle_version": 42,
  "policy_revision": 17,
  "audience": {
    "installation_id": "00000000-0000-0000-0000-000000000000",
    "org_id": "00000000-0000-0000-0000-000000000000",
    "workspace_id": "00000000-0000-0000-0000-000000000000"
  },
  "bundle_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "accepted_at": "2026-01-01T12:00:00Z",
  "expires_at": "2026-01-01T13:00:00Z",
  "reason_code": "refresh_failed",
  "last_check": "2026-01-01T12:05:00Z",
  "last_success": "2026-01-01T12:00:00Z",
  "state": "stale_but_valid"
}
```

| Field | Meaning |
|---|---|
| `highest_bundle_version` | Version of the active bundle. It is also the rollback watermark for this audience. |
| `policy_revision` | The catalog policy revision the bundle was built from. |
| `audience` | Installation, org and workspace the bundle is bound to. |
| `bundle_digest` | `sha256:` digest of `bundle.json`, sent as `If-None-Match`. |
| `accepted_at` | When the runtime activated the bundle. |
| `expires_at` | The bundle's `not_after`. Decisions deny from this time. |
| `reason_code` | The last problem recorded: `refresh_failed` after a `409`, `401`/`403` or other error status; `integrity_rejected` or `schema_unsupported` after a rejected candidate; `runtime_revoked`. Cleared by a successful refresh. |
| `last_check` | The last refresh attempt that failed or returned `200`/`304`. |
| `last_success` | The last `200` or `304`. `stale_after_seconds` is measured from here. |
| `state` | The state last written by a check or refresh. |

`state` on disk is only rewritten when the runtime checks or refreshes, so
it can lag. `kei-proxy policy show`, or `GET /v1/policy-bundle/status` on
the authenticated `serve` socket, revalidates the bundle and recomputes
`expired` and the `stale_after_seconds` window. It does not apply the v2
subject-snapshot check, so for up to `stale_after_seconds` it can report a
v2 bundle as `active` while decisions deny with `subject_snapshot_stale`.
Compare `issued_at` with the current time to tell the two apart. Both also
report `bundle_schema`, `not_after`, `poll_interval_seconds` and
`stale_after_seconds`. Neither includes policies, subjects or credentials.

A `reason_code` of `refresh_failed` with an advancing `last_check` and a
fixed `last_success` means refreshes are being refused. Check the warn log
for `http_status` and `detail`. A `409` names the catalog condition above.
