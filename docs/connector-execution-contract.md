# Connector execution contract

Status: **Proposed** (layer 1 of the connector-exec stack). Layers 2 (runtime
execution) and 3 (catalog descriptor) implement it once the decisions in
[Open decisions](#open-decisions) are confirmed.

Today `kei-proxy connector invoke` returns only the catalog's decision and
envelope. The provider clients exist in `kei-policy-catalog`'s
`pkg/connectors/providers`, but nothing calls them, and `invoke` has no way to
carry a query. So every governed connector call returns no data. This
document defines how the tenant-side runtime executes the provider call
itself, as ADR-011 requires. The catalog stays the metadata and decision
control plane, and it never executes a provider or sees a payload, result,
or credential value.

Sources: kei ADR-011 (data plane), ADR-012 (governance pivot), ADR-014
(identity propagation), ADR-017 (contracts module), ADR-020 (one installation
credential), ADR-026 (policy bundle, proposed), `docs/connector-secret-references.md`,
`docs/oauth-connector-gaps.md`; `kei-policy-catalog` `connector_invoke.go`,
`pkg/connectors`; `kei` `cmd/oidc-bridge/connectors`; MarketingSite
`src/worker/routes/crm.ts`, `src/worker/kei/*`.

## 1. Supported connectors

The runtime executes only the providers we build. A connector whose provider is
not on this list is denied with `provider_not_supported` before any credential
is resolved.

| Provider | Credential path | Account models | Status |
| --- | --- | --- | --- |
| `gmail` | OAuth relay (path 2), or shared secret for domain-wide delegation | per-user (default), shared, domain delegation | supported |
| `google_drive` | OAuth relay (path 2), or shared secret for domain-wide delegation | per-user (default), shared, domain delegation | supported |
| `linear` | OAuth relay (path 2) | per-user (default), shared | supported |
| `github` | OAuth relay (path 2) | per-user (default), shared | supported |
| `tito` | shared secret (path 1) | n/a | supported |
| `crm` | shared secret (path 1) plus a Kei service assertion | n/a | supported |
| `notion` | n/a | n/a | later (HAI-216) |
| `http_api` | shared secret (path 1) | n/a | **open decision** (D4) |
| `s3` | n/a | n/a | **removed**: S3 is storage, not a connector. The runtime denies it; removing the provider code and the catalog CHECK value is a separate ticket. |
| `freshbooks`, `mercury` | n/a | n/a | not supported (present in `kei-connector-contracts`, not built) |

## 2. Invoke flow

```
harness
  │  kei-proxy connector invoke --connector <uuid> --capability C --action A
  │      --resource R --input '<json>' [--user U | --provider-user P]
  ▼
kei-proxy (tenant runtime)
  1. validate input against the capability's input schema   (local, no I/O)
  2. input_digest = sha256(canonical JSON of input)
  3. POST /api/v1/data-connectors/invoke  ──────────────────► catalog
         (runtime token, connector, capability, resource,       decides: structure,
          subject, input_digest; never the input itself)        agent binding, policy,
                                                                approval (consumed),
     ◄──── allow + connector descriptor                         mints grant/assertion
           + credential_grant (OAuth) | service_assertion (crm)
  4. resolve the credential
       path 1: SecretStore.Get(credential_backend, credential_ref)
       path 2: POST <bridge>/oauth/credentials:relay {grant} ──► oidc-bridge
  5. execute the provider call                   (contracts/providers client)
  6. redact the result per capability           (typed allowlist, size cap)
  7. emit the audit event                        (digests only, section 8)
  8. write the result JSON to stdout, exit 0
```

Rules:

- The input never leaves the runtime. The catalog gets only `input_digest`, so
  it can bind the decision (and an approval) to the exact input without seeing
  the query.
- Every step fails closed. Any failure after step 3 returns a deny with a
  `reason_code` (section 7) and **no partial data**.
- The decision stays online in this contract. When ADR-026 bundles land, the
  runtime may decide locally, but connector execution still calls the catalog:
  the OAuth grant, the CRM assertion, and approval consumption (HAI-214) are
  online by design. This contract does not touch the bundle loader or the
  state-dir code (HAI-219).
- The runtime holds a resolved credential only for the duration of one call.
  It is never written to stdout, logs, audit, the spool, or a cache. The
  existing 5-minute token cache in `oidc_bridge.go` is not used on this path.

### CLI surface (layer 2)

```
kei-proxy connector invoke
  --connector <uuid>           connector instance id (required; a provider name is rejected)
  --capability <name>          e.g. message.search (required)
  --action <read|create|...>   must equal the capability's action (required)
  --resource <resource>        provider resource grammar, section 5 (required)
  --input <json>|@<file>|-     capability input; '-' reads stdin; default {}
  --user <kei user id>         invoking Kei user (or --user-id, existing alias)
  --provider-user <id>         chat-platform identity, e.g. WhatsApp E.164 (+15551234567);
                               also KEI_PROXY_PROVIDER_USER
  --approval-id <id>           required for non-read capabilities
  --idempotency-key <key>      required for non-read capabilities
  --timeout <seconds>          whole-call deadline, default 30
```

The existing identity-propagation flags and variables (`--trace-id` /
`KEI_PROXY_SPAN_ID`, `--invoking-subject`, `--framework`) are unchanged.
`KEI_RUNTIME_TOKEN` comes from the environment only.

### stdout

Allow, exit 0:

```json
{
  "decision": "allow",
  "trace_id": "4f0c…",
  "connector_id": "8b1e…",
  "provider": "gmail",
  "capability": "message.search",
  "result": { "messages": [ … ], "next_page_token": "…" },
  "audit": { "input_digest": "sha256:…", "result_digest": "sha256:…", "result_bytes": 5120 }
}
```

Deny or error, exit 1:

```json
{
  "decision": "deny",
  "reason_code": "oauth_not_connected",
  "reason": "no gmail connection for this user",
  "enrollment": { "url": "…", "expires_at": "…" },
  "connect": { "provider": "gmail", "url": "…" }
}
```

`enrollment` is passed through unchanged from the catalog, as in `authorize`
(HAI-209). `connect` appears only on `oauth_not_connected` and
`oauth_reconnect_required`, when the catalog supplies a connect link. The
harness must show `url` privately to the user, never in a channel and never in
a log. For compatibility, the pre-contract fields `reason` and `envelope` are
kept, and any non-zero exit is a deny.

## 3. Credential paths

The two paths are never mixed. A connector's `credential_source` selects
exactly one, and the runtime never falls back from one path to the other.

### Path 1: shared secret (`credential_source = opaque_ref`)

Used by: `tito` (API token), `crm` (the Worker's `X-KEI-API-Key`), `http_api`
(if kept), and Google domain-wide delegation (the service-account key).

- The connector stores only `credential_ref`, an opaque pointer that passes
  `ValidateCredentialRef`. The catalog adds `credential_backend` (one of
  `aws-secrets-manager`, `azure-key-vault`, `gcp-secret-manager`) from the
  organization's credential-store installation, the same store that model
  profiles use.
- The runtime resolves it with the same `SecretStore` registry as the
  model-profile path (`model_invoke.go`, `secret_store.go`), using workload
  identity: `SecretStore.Get(credential_backend, credential_ref)`.
- The runtime has no GCP backend yet (HAI-137 is catalog-only), so a
  `gcp-secret-manager` connector denies `credential_backend_unavailable` until
  that runtime slice lands.
- The secret value never enters the catalog, the invoke response, or audit.
  Setup writes it through sealed credential delivery (section 9).

### Path 2: user-delegated OAuth (`credential_source = oauth`)

Used by: `gmail`, `google_drive`, `linear`, `github` (per-user and shared
account models).

- The runtime never holds `OIDC_BRIDGE_SECRET`. ADR-020 says a customer
  runtime receives no service secret, and the current relay
  (`GET /oauth/credentials/{user_id}/{provider}`) is authenticated with
  exactly that secret. So this contract adds a relay method authenticated by a
  **credential grant** instead (decision D2):
  - On an allow for an OAuth connector, the catalog mints `credential_grant`:
    a compact JWS, ES256, `iss=kei-policy-catalog`, `aud=oidc-bridge`,
    `exp <= iat + 60s`, a unique `jti`. Its claims are `tenant_id`,
    `workspace_id`, `connector_id`, `provider`, `account_model`, `trace_id`,
    `scopes`, and exactly one binding: `kei_user_id` (per-user) or
    `credential_ref` (shared).
  - The runtime calls `POST <OIDC_BRIDGE_URL>/oauth/credentials:relay` with
    body `{"grant": "<jws>"}`. The bridge verifies the grant against the
    catalog's published key, consumes `jti` (single use), loads the bound token
    row, re-checks the row's tenant/workspace/subject binding, refreshes the
    token if it has expired, and returns
    `{access_token, token_type, expires_in, account_email_digest}`. It never
    returns the raw account email.
- The access token lives only for the call. Refresh tokens never leave the
  bridge.
- ADR-011 note: the bridge is a Kei-hosted token store, so an access token
  does cross from Kei to the tenant runtime for each call. This is the
  documented current placement (ADR-011 Consequences), unchanged here. The
  token never transits the catalog.

## 4. OAuth account models

For each OAuth connector instance, whose account (whose email) a token belongs
to is an explicit choice, stored as `account_model` on the connector row.

### (a) Per-user (`per_user`): the default, and the model for PDE Gmail

Each Kei user connects their own account. The runtime always uses the token
of the **invoking** Kei user.

- **Identity chain (WhatsApp/PDE):** WhatsApp E.164 phone →
  `web.chat_identities` link (created when the WhatsApp claim is redeemed,
  kei-policy-catalog #78) → Kei user id → that user's bridge token row for the
  provider. The harness sends `--provider-user +15551234567` on a `whatsapp`
  installation. The catalog resolves the Kei user; an unlinked phone gets
  `enrollment_required` with the claim link, exactly as `authorize` does. The
  same chain applies to Discord and Teams, with their own platform ids.
- **Binding in the bridge:** the token row `(user_id = kei_user_id, provider)`,
  bound to `tenant_id`, `workspace_id`, and `subject = kei_user_id`, with
  `credential_source = oauth`.
- **What the runtime sends:** a grant with `account_model=per_user` and
  `kei_user_id=<resolved invoking user>`. The catalog sets `kei_user_id`; the
  harness cannot choose it.
- **Invariant:** a per-user connector never falls back to another user's
  token or to a shared token. No row for the invoking user means a deny with
  `oauth_not_connected` and a connect link.
- **Account email:** stored on the **bridge token row** in a new column
  `account_email`, field-encrypted like the tokens. It is not stored on the
  identity profile, because it belongs to one grant: one Kei user may consent
  a different Google account per provider, and the email must disappear when
  the grant is revoked. The bridge already resolves the email at callback
  (`ResolveIdentity`); today it only forwards it on the redirect.
- **Shown to the user:** on the provider's consent screen and on the bridge's
  post-connect confirmation ("Connected Gmail as j…@example.com"), and in
  connector state: the console connections list, and the chat harness's
  connect/status reply (sent privately). The owning user sees the full email.
  Admins see status plus a masked email for per-user rows.
- **Re-link:** the user runs the connect flow again (from the console, or from
  a chat harness, which sends the connect link privately). The callback
  overwrites the user's row for that provider, keeps its `credential_ref`, and
  stores the new email.
- **Revocation:** the user disconnects in the console, or an admin calls
  `DELETE /oauth/credentials/...`. The bridge revokes at the provider (best
  effort) and deletes the row; the next call denies `oauth_not_connected`. A
  revoke on the provider side surfaces as a failed refresh: the bridge returns
  409, deletes the row, and the runtime denies `oauth_reconnect_required`.
  Suspending the connector in the catalog denies every user.
- **Audit:** `credential_subject = kei_user_id` and
  `account_email_digest`. The raw email never appears in audit.
- **Supported today:** the token row, its binding, `UNIQUE(user_id, provider)`,
  the connect flow, and revoke. **New:** the `account_email` column; the
  grant-authenticated relay; `account_model` on the connector; a per-user
  connector with an empty `subject` (the catalog currently requires `subject`
  on every OAuth connector and fails `ValidateCall` when the invoker differs,
  so each user would need their own connector row). Also new: widening the
  unique key to `(user_id, provider, tenant_id, workspace_id)` so one user can
  connect in two workspaces. Known bridge bug to fix first: `oauth_states`
  does not persist `connector_provider`, so a Gmail callback with a database
  dispatches as `google_drive`.

### (b) Shared workspace account (`shared`)

An admin connects one account for the connector instance, and every user
the policy allows reads it (for example a shared `events@` mailbox).

- **Binding in the bridge:** exactly one token row per connector instance,
  referenced by the connector's unique `credential_ref`. The row is bound to
  tenant/workspace and `subject = connector:<connector_id>`, a service subject
  rather than the admin who connected it.
- **What the runtime sends:** a grant with `account_model=shared` and
  `credential_ref`.
- **Gating:** ABAC policy decides who may invoke. `ValidateCall` must not
  compare the invoker to the credential subject for shared connectors. This
  is a contract change: today it fails closed on any mismatch.
- **Revocation:** an admin disconnects the connector (the row is deleted, and
  every user denies `oauth_not_connected`) or suspends it in the catalog. A
  provider-side revoke works as in (a).
- **Audit:** `invoking_subject = <invoking Kei user>`,
  `credential_subject = connector:<id>`, and `account_email_digest`.
- **Supported today:** the closest existing shape: `credential_source=oauth`,
  a unique `credential_ref`, and a single `subject`. **New:** the
  service-subject binding, the shared-model exemption from the subject match,
  and the connect flow run by an admin for a connector rather than for
  themselves.

### (c) Google Workspace domain-wide delegation (`domain_delegation`)

Only for `gmail` and `google_drive` on a Google Workspace domain.

- **Binding:** none in the bridge. The service-account key JSON is a
  **shared secret (path 1)** in the customer's secret manager
  (`credential_source=opaque_ref`). The impersonated mailbox is non-secret
  connector config, `impersonate_email`.
- **What the runtime does:** it resolves the key through `SecretStore`, signs
  a JWT-bearer assertion (`iss` = the key's `client_email`,
  `sub=impersonate_email`, `scope` = the connector's fixed scope, `exp`
  ≤ 1h), and exchanges it at `https://oauth2.googleapis.com/token` for an
  access token. Nothing is cached beyond the call. The bridge is not involved.
- **Variant, not the default:** impersonate the invoking user's own Workspace
  address instead of a fixed mailbox. This needs a verified mapping from the
  Kei user to the Workspace email, and it is left to a later decision.
- **Revocation:** the Workspace admin removes the client id from domain-wide
  delegation, or deletes or rotates the key. On the Kei side, suspend the
  connector.
- **Audit:** `credential_subject = connector:<id>`,
  `account_email_digest` of `impersonate_email`.
- **Supported today:** nothing. **New:** the account model, the
  `impersonate_email` config, and the runtime JWT exchange (standard library
  `crypto/rsa`; no new dependency).

### Allowed models per provider

| Provider | per_user | shared | domain_delegation | Default |
| --- | --- | --- | --- | --- |
| gmail | yes | yes | yes | per_user; always per_user for chat harnesses (PDE) |
| google_drive | yes | yes | yes | per_user |
| linear | yes | yes | no | per_user |
| github | yes | yes | no | per_user |

Connectors used from chat harnesses (WhatsApp, Discord, Teams) default to
per-user. Shared and delegation are opt-in by an admin, per connector.

### Email digest

`account_email_digest = "hmac-sha256:" + hex(HMAC-SHA256(k_tenant, lower(trim(email))))`,
computed by the bridge with a per-tenant key the bridge holds. The digest is
stable within a tenant, so an auditor can tell whether two calls used the same
account, but a dictionary attack outside Kei cannot reverse it. A plain
sha256 would be reversible. See decision D5.

## 5. Capability inputs and results (reads)

Inputs are validated locally before step 3. An unknown field, a wrong type, or
a value over its limit denies `input_invalid`. Every input is at most 16 KiB.
Results are re-encoded from typed structs, so only listed fields can appear.

| Provider | Capability | Resource | Input | Result |
| --- | --- | --- | --- | --- |
| gmail | `message.search` | `gmail/messages` | `{query?: string ≤512 (Gmail syntax), page_size?: 1..25 (default 10), page_token?: string ≤256}` | `{messages: [GmailMessage], next_page_token?}`; bodies are never returned |
| gmail | `message.get` | `gmail/messages/<id>` | `{message_id?}` (must equal the resource id if set) | `GmailMessage` |
| google_drive | `drive.search` | `drive/<drive_id>` | `{query: string 1..512}` | `{files: [{id, drive_id, name, mime_type, modified_at}]}` |
| google_drive | `drive.metadata.read` | `drive/<drive_id>/files/<file_id>` | `{}` | `{id, drive_id, name, mime_type, modified_at}` |
| google_drive | `docs.read` | `drive/<drive_id>/files/<file_id>` | `{}` | `{id, name, mime_type, text}`, with `text` capped at 256 KiB (a larger document is `result_too_large`) |
| linear | `issue.read` | `linear/issue/<id>` | `{}` | `{id, identifier, team_key, project_id?, title, state}` |
| linear | `team.read` / `project.read` / `cycle.read` | `linear/team/<key>` / `linear/project/<id>` / `linear/cycle/<id>` | `{}` | the provider's typed struct |
| github | `repository.read`, `issue.read`, `pull_request.read`, `check.read`, `workflow.read` | existing contract resources | `{}` | the provider's typed struct |
| tito | `event.list` | `tito/<account>/events` | `{status?: upcoming (default) \| past \| archived, page?: ≥1}` | `{events: [TitoEvent], next_page?}` |
| tito | `event.get` | `tito/<account>/events/<event>` | `{}` | `TitoEvent` |
| tito | `release.list` | `tito/<account>/events/<event>/releases` | `{}` | `[TitoRelease]` |
| tito | `ticket.summary` | `tito/<account>/events/<event>/ticket-summary` | `{}` | `{account_slug, event_slug, total, by_state, by_release}`; fails closed above 5000 tickets |
| crm | `lead.read` | `leads`, `leads/<id>`, `customers`, `customers/<id>` | `{}` | `{records: [Lead]}` or `{record: Lead}` |

Redaction per capability:

- **Gmail:** `GmailMessage` is `{message_id, thread_id, internal_date, from, to,
  subject, labels, snippet, body?}`. `body` is present only on `message.get`,
  and only when the connector policy sets `gmail_include_body=true`; otherwise
  the provider requests `format=metadata`, so a body is never even fetched.
  Attachments and other headers are never returned.
- **Drive:** file content only through `docs.read`. Search and metadata
  never return content.
- **Tito:** no attendee PII (names, emails, phones, answers). No capability
  lists tickets.
- **Linear:** no descriptions or comments in `issue.read`.
- **CRM:** a Lead is `{id, company_name, contact_name, email, role, status,
  priority, source, tier, created_at, updated_at}`. Free text (`message`,
  `early_access_notes`, audit answers) is dropped even if the Worker returns
  it.

The CRM Worker (`POST /api/crm/v1/invoke`) needs two credentials on every
call:

1. `X-KEI-API-Key`: the Worker's `CRM_CONNECTOR_API_KEY` (path 1).
2. `Authorization: Bearer <service_assertion>`: an ES256 JWT that the catalog
   mints on allow. `iss` and `aud` match the Worker's
   `KEI_SERVICE_ASSERTION_ISSUER`/`_AUDIENCE`, `exp` is at most 300s away, and
   the `jti` is single-use. The claims are the Worker's `claimsSchema`:
   tenant, workspace, subject, agent, connector, `provider=crm`, connector
   status, capabilities, policy, capability, action, resource, trace id,
   optional idempotency key, and optional approval id.

The runtime forwards the assertion unmodified and sends
`{"data": <input.data>}` as the body. A Worker 401 or 403 maps to
`provider_denied`. The `/api/leads` API (key only, no assertion) belongs to
`http_api`, not to `crm`.

## 6. Where the provider code lives

**Decision D1: `github.com/HaikeiLabs/kei-connector-contracts`, as a Go
dependency.** The runtime already requires v0.1.0 (for `http_runtime.go`), and
ADR-017 names this module the extraction seam.

| Option | For | Against |
| --- | --- | --- |
| **Shared module `kei-connector-contracts` (chosen)** | Already a runtime dependency, stdlib-only, frozen by tests; a single copy for the catalog, runtime, and `kei` tests; no catalog server code in the runtime's module graph | The catalog's in-tree `pkg/connectors` has diverged (gmail, tito, `credential_source`, `subject` exist only there; notion, freshbooks, and mercury exist only in the module). It must be converged first: an additive v0.2.0 release before layer 2 can merge. |
| Import `kei-policy-catalog/pkg/connectors/providers` | Gmail and Tito are already there | Pulls the catalog module (pgx, the server) into the runtime's `go.mod`, couples releases, and puts provider code one import away from the catalog server path |
| Vendor into the runtime | No cross-repo wait | A third drifting copy; the freeze tests don't cover it |

Plan: a `kei-connector-contracts` PR (v0.2.0) adds `ProviderGmail`,
`ProviderTito`, `CredentialSource`, `Subject`, `AccountModel`,
`GmailIncludeBody`, the gmail/tito clients, and the per-provider setup schema
(section 9). Existing freeze assertions are unchanged; new ones pin the
additions. The runtime bumps to v0.2.0 in layer 2. A separate ticket switches
the catalog to import the module and delete its fork.

**Invariant:** nothing on the catalog's server path calls a provider client.
The catalog uses only metadata validation (`Metadata.Validate`,
`ValidateCall`, `Decide`). A catalog test asserts that no non-test catalog
package imports `.../providers`.

## 7. Errors and fail-closed rules

Every row denies (exit 1) and returns no result data.

| reason_code | When |
| --- | --- |
| `input_invalid` | Input fails the capability schema, is over 16 KiB, or is not JSON |
| `catalog_unavailable` | The catalog is unreachable, returns non-200, or returns a malformed body |
| `policy_deny` | The catalog denies (binding, policy, structure); the catalog's `reason` is passed through |
| `approval_required` | Non-read capability without a valid, unconsumed approval |
| `enrollment_required` | The chat identity is not linked; carries `enrollment` |
| `descriptor_invalid` | An allow without a connector descriptor, or a descriptor that fails `Metadata.Validate`, or a provider/capability mismatch with the request |
| `provider_not_supported` | Provider not in section 1 |
| `credential_backend_unavailable` | The backend is not registered in this runtime (e.g. GCP today) |
| `credential_unavailable` | Secret missing, empty, or unreadable (path 1); the reference is never echoed |
| `oauth_not_connected` | Relay 404: no token row for the binding |
| `oauth_reconnect_required` | Relay 409: refresh failed or expired with no refresh token (row deleted) |
| `oauth_binding_mismatch` | Relay 403: row bound to another tenant, workspace, or subject |
| `oauth_grant_rejected` | Relay rejects the grant: signature, audience, expiry, or replayed `jti` |
| `oauth_relay_unavailable` | Bridge unreachable or 5xx. This is **not** mapped to enrollment, unlike the legacy `authorize` path. |
| `provider_denied` | Provider 401 or 403 |
| `provider_not_found` | Provider 404 |
| `provider_rate_limited` | Provider 429 |
| `provider_error` | Other provider failure; only the status class is recorded |
| `provider_timeout` | Provider deadline exceeded |
| `result_too_large` | Raw provider response over 4 MiB, or redacted result over 1 MiB |

Timeouts, all inside the `--timeout` budget (default 30s): catalog 10s,
credential resolution 5s, provider 15s. Reads are not retried in layer 2, and
writes are never retried by the runtime (the harness retries with the same
`--idempotency-key`). Errors and logs never include the credential, the
reference, the input, the result, provider response bodies, or the account
email.

## 8. Audit

Two records per call, both metadata only (ADR-011):

1. **Decision:** the catalog writes it at step 3 (`audit_records`, as today).
   It gains `input_digest`.
2. **Execution:** the runtime appends it to the `KEI_PROXY_AUDIT` JSONL, and
   `collector` ships it as event type `connector_execution`. It carries
   `span_id` (= `trace_id`), `invoked_at`, `org_id`, `workspace_id`,
   `agent_id`, `invoking_subject`, `connector_id`, `provider`, `capability`,
   `action`, `resource`, `credential_source`, `account_model`,
   `credential_subject` (Kei user id, or `connector:<id>`),
   `account_email_digest` (OAuth and delegation only), `input_digest`,
   `result_digest`, `result_bytes`, `result_items`, `provider_status_class`
   (`2xx`/`4xx`/`5xx`/`timeout`), `decision`, `reason_code`, `duration_ms`,
   `approval_id`, and `idempotency_key`.

The record never carries the input, query, result, snippet, email address,
token, secret, or credential reference.

## 9. Per-provider setup schema

Connector setup, in the CLI and the web UI, renders from one machine-readable
schema, `kei.connector-setup/v1`, published in `kei-connector-contracts`
v0.2.0 as Go data plus a JSON export. Each provider declares its
authentication options and fields:

```json
{
  "schema": "kei.connector-setup/v1",
  "provider": "tito",
  "auth": [{ "credential_source": "opaque_ref" }],
  "fields": [
    { "name": "account_slug", "type": "string", "required": true, "secret": false,
      "pattern": "^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$", "label": "Tito account slug" },
    { "name": "api_token", "type": "string", "required": true, "secret": true,
      "min_length": 20, "max_length": 256, "pattern": "^\\S+$", "label": "Tito API token" }
  ]
}
```

| Provider | Auth choice | Non-secret fields (connector `config`) | Secret field (at most one per connector) |
| --- | --- | --- | --- |
| gmail | OAuth + `account_model` ∈ {per_user, shared, domain_delegation} | `include_body` (bool, default false → `gmail_include_body`); delegation: `impersonate_email` (email) | delegation only: `service_account_key` (JSON; must have `type=service_account`, `client_email`, `private_key`) |
| google_drive | OAuth + `account_model` ∈ {per_user, shared, domain_delegation} | `drive_id` (optional, `^[A-Za-z0-9_-]{1,128}$`); delegation: `impersonate_email` | delegation only: `service_account_key` |
| linear | OAuth + `account_model` ∈ {per_user, shared} | none | none |
| github | OAuth + `account_model` ∈ {per_user, shared} | none | none |
| tito | shared secret | `account_slug` | `api_token` |
| crm | shared secret | `base_url` (https, the MarketingSite origin; no userinfo, query, or fragment; host must resolve to a public address) and `assertion_audience` (must equal the Worker's `KEI_SERVICE_ASSERTION_AUDIENCE`) | `api_key` (≥ 32 chars, the Worker's `CRM_CONNECTOR_API_KEY`) |

How the values flow:

- **OAuth:** setup records `account_model`. For `per_user`, nothing is
  collected; each user connects on first use or from the console. For
  `shared`, the admin completes the bridge connect flow for the connector.
- **Non-secret fields** are stored in a new `config` JSONB on
  `abac.data_connectors`, validated server-side against the same schema, and
  returned in the invoke descriptor.
- **Secret fields never reach the catalog in plaintext.** The CLI or browser
  seals the value to each target runtime installation's credential-sync key
  (the same sealed-delivery path model profiles use). The catalog stores only
  ciphertext and generates
  `credential_ref = <store prefix>-connector-<connector_id>`. The runtime's
  `kei-proxy credential sync` decrypts the value, `Put`s it into the secret
  manager, and acks. The connector stays `pending` until the ack, then becomes
  `active`.
- **Bring your own reference:** instead of a value, an operator may enter an
  existing reference (for example `kei/prod/crm/connector-api-key`, as
  provisioned by MarketingSite's `provision-crm-connector-key.sh`). It must
  pass `ValidateCredentialRef`, and `credential sync` must check it with
  `SecretStore.Validate` (new behavior) before the connector becomes `active`.
- Validation errors name the field and never echo a submitted value.

## 10. Writes (a later layer)

Writes are approval-gated and not implemented in layer 2: Linear
`issue.create`/`issue.update`, GitHub mutations, CRM
`lead.create`/`lead.update`. Drive `share` is not in the capability registry
(see the HAI-207 contract gap). Rules for that layer:

- `--approval-id` and `--idempotency-key` are required. The catalog consumes
  the approval atomically with the decision (HAI-214, single use) and binds it
  to `input_digest`, so an approval cannot be reused with a different payload.
- The runtime never retries a write.
- CRM writes currently pass **two** approval checks: the catalog's, and the
  Worker's D1 `crm_approvals` copy. This must be reconciled before CRM writes
  ship, either by having the Worker trust the approval id in the
  catalog-signed assertion or by syncing the two stores. It is tracked as a
  follow-up, not decided here.

## 11. Catalog changes (layer 3)

The invoke allow response gains a non-secret `connector` descriptor. The
current handler comment says "the caller already holds the connector's
credential reference", which is not true for a tenant runtime.

```jsonc
{
  "decision": "allow",
  "capability": { … }, "envelope": { … }, "audit_record": { … },
  "connector": {
    "id": "…", "provider": "gmail", "status": "active",
    "credential_source": "oauth", "account_model": "per_user",
    "credential_ref": "…",           // opaque_ref only
    "credential_backend": "aws-secrets-manager", // opaque_ref only
    "config": { "include_body": false },
    "policy": { "gmail_include_body": false }
  },
  "credential_subject": "<kei user id> | connector:<id>",
  "credential_grant": "<jws>",      // oauth only
  "service_assertion": "<jwt>"      // crm only
}
```

The request gains `provider_user_id` (chat identity; resolved to the Kei user
through `chat_identities`, with `enrollment_required` when unlinked, as
`authorize` does) and `input_digest`. Field names avoid the substring
`secret` because of the API redaction guard. Signing keys: one ES256 key pair
per purpose (`kid` scoped to `oidc-bridge` or the CRM audience), with public
keys published for the bridge and the Worker. The bridge relay method and
`account_email` column are a separate `kei` stack. Layer 2 runs against a
fixture bridge until that stack lands.

## Open decisions

The user decided the PDE Gmail account model: **per-user** (section 4a). These
still need confirmation:

- **D1: provider code home.** Converge in `kei-connector-contracts` v0.2.0
  (recommended), which requires a contracts release before layer 2 merges.
- **D2: OAuth relay authentication.** A catalog-minted, single-use,
  60-second credential grant presented to a new bridge
  `POST /oauth/credentials:relay` (recommended), versus giving runtimes
  `OIDC_BRIDGE_SECRET` (violates ADR-020) or having the catalog proxy the token
  (the token would transit the catalog).
- **D3: CRM assertion issuer.** The catalog mints the ES256 service assertion
  on allow, with a new catalog signing key whose public key is provisioned to
  the Worker as `KEI_SERVICE_ASSERTION_PUBLIC_KEY`.
- **D4: `http_api` status.** Keep the existing `ExecuteHTTP` path as a
  supported generic connector, or freeze it (deny new connectors) now that
  `crm` has its own provider.
- **D5: account email storage and digest.** The email lives on the bridge
  token row, and audit uses a per-tenant keyed HMAC digest (recommended),
  versus a plain sha256 that is reversible by dictionary.
