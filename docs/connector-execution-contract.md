# Connector execution contract

Status: **Accepted**. Decisions D1–D5 were settled by the user on 2026-09-28
(see [Decisions](#decisions)). Implementation order: `kei-connector-contracts`
v0.2.0, then runtime execution (layer 2, against fakes), then the catalog
descriptor and token proxy (layer 3).

Today `kei-proxy connector invoke` returns only the catalog's decision and
envelope. The provider clients exist in `kei-policy-catalog`'s
`pkg/connectors/providers`, but nothing calls them, and `invoke` has no way to
carry a query. So every governed connector call returns no data. This
document defines how the tenant-side runtime executes the provider call
itself, as ADR-011 requires. The catalog stays the metadata and decision
control plane, and it never executes a provider or sees a payload or result.
It never sees a shared-secret value. It does relay a user-delegated OAuth
access token in memory for one allowed call (D2, section 3).

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
| `gmail` | OAuth token proxied by the catalog (path 2), or shared secret for domain-wide delegation | per-user (default), shared, domain delegation | supported |
| `google_drive` | OAuth token proxied by the catalog (path 2), or shared secret for domain-wide delegation | per-user (default), shared, domain delegation | supported |
| `linear` | OAuth token proxied by the catalog (path 2) | per-user (default), shared | supported |
| `github` | OAuth token proxied by the catalog (path 2) | per-user (default), shared | supported |
| `tito` | shared secret (path 1) | n/a | supported |
| `crm` | shared secret (path 1), plus a service assertion signed by the runtime's installation key (D3) | n/a | supported |
| `http_api` | shared secret (path 1) | n/a | supported: a generic governed connector with one allow-listed base URL (D4) |
| `notion` | n/a | n/a | later (HAI-216) |
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
  3. POST /api/v1/data-connectors/invoke  (TLS) ────────────► catalog
         (runtime token, connector, capability, resource,       decides: structure,
          subject, input_digest; never the input itself)        agent binding, policy,
                                                                approval (consumed);
                                                                on allow for OAuth:
                                                                GET bridge token ──► oidc-bridge
     ◄──── allow + connector descriptor                         (bridge secret stays
           + oauth {access_token, expires_at} (OAuth only)      in the control plane)
  4. resolve the credential
       path 1: SecretStore.Get(credential_backend, credential_ref)
       path 2: use the oauth access token from step 3 (this call only)
       crm:    also sign the service assertion with the installation key (D3)
  5. execute the provider call                   (contracts/providers client)
  6. redact the result per capability           (typed allowlist, size cap)
  7. emit the audit event                        (digests only, section 8)
  8. write the result JSON to stdout, exit 0
```

Rules:

- The input never leaves the runtime. The catalog gets only `input_digest`, so
  it can bind the decision (and an approval) to the exact input without seeing
  the query. Validation runs in two phases, both before any credential or
  provider call. Before the catalog call, the input must be one JSON object of
  at most 16 KiB. After the descriptor names the provider, a strict
  per-capability decode rejects unknown fields and out-of-range values. The
  digest is `sha256` of the canonical encoding (sorted keys, numbers as
  written).
- Every step fails closed. Any failure after step 3 returns a deny with a
  `reason_code` (section 7) and **no partial data**.
- The decision stays online in this contract. When ADR-026 bundles land, the
  runtime may decide locally, but connector execution still calls the catalog:
  the OAuth token and approval consumption (HAI-214) are online by design.
  This contract does not touch the bundle loader or the state-dir code
  (HAI-219).
- The runtime holds a resolved credential only for the duration of one call.
  It is never written to stdout, logs, audit, the spool, or a cache. The
  runtime does not call the bridge on this path, so the existing 5-minute
  token cache in `oidc_bridge.go` is not involved.

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

Used by: `tito` (API token), `crm` (the Worker's `X-KEI-API-Key`),
`http_api` (the injected key), and Google domain-wide delegation (the
service-account key). The runtime's CRM assertion signing key (D3) is read
through the same store, but it belongs to the installation, not to a connector
(section 5).

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

**Decision D2: the catalog proxies the token.** The runtime never calls the
bridge and never holds `OIDC_BRIDGE_SECRET` (ADR-020).

1. The catalog finishes the whole decision first: structure, agent binding,
   ABAC policy, and approval. Only when the final decision is `allow` does it
   fetch a token, and only for that decision's (invoking Kei user, connector,
   capability).
2. The catalog calls the existing bridge relay server to server, with the
   bridge secret, which stays in the control plane:
   `GET /oauth/credentials/{user_id}/{provider}?tenant_id=…&workspace_id=…&subject=…`.
   The binding comes from the account model (section 4): per-user uses
   `user_id = subject = <invoking Kei user id>`; shared uses
   `user_id = subject = connector:<connector_id>`. The bridge checks the
   binding (403 on mismatch) and refreshes an expired token.
3. The catalog returns the token in the invoke response, under
   `oauth: {access_token, token_type, expires_at, account_email_digest?}`
   (section 11).
4. The runtime uses the token for this one provider call and then drops it.

Requirements (layer 3 and layer 2 each test them):

- **Short-lived:** `expires_at` is a use-by time,
  `min(the provider token's expiry, now + 60s)`. The runtime refuses a token
  past `expires_at` (`oauth_token_expired`). Some provider tokens (GitHub
  OAuth apps, for example) don't expire on their own, which is why the next
  rule matters.
- **Never persisted:** the catalog does not write the token to a table, cache,
  `audit_records`, or `envelope`. The runtime does not write it anywhere.
- **Never logged:** neither side logs the token or the response body. The
  catalog's logger already redacts `token` keys, and the invoke handler must
  not log the response.
- **Never in audit:** audit records carry `account_email_digest` and the
  credential subject, never the token.
- **TLS only:** the catalog sets `Cache-Control: no-store`. The runtime
  refuses an `oauth` block received over plain HTTP
  (`insecure_transport`), unless the control-plane host is loopback (for
  local tests). This means local compose (`host.docker.internal` over http)
  cannot run OAuth connectors.
- **Only on a matching allow:** a deny response never carries `oauth`. The
  runtime checks that `oauth` is present exactly when the descriptor says
  `credential_source=oauth`, and that the descriptor's connector and
  capability equal the request's; any mismatch is `descriptor_invalid`.
- **Bridge failures become catalog denies** (section 7): bridge 404 →
  `oauth_not_connected`, 409 → `oauth_reconnect_required`, 403 →
  `oauth_binding_mismatch`, unreachable or 5xx → `oauth_bridge_unavailable`.
  None of them falls back to another credential.

ADR-011 note: the OAuth access token transits the control plane **in memory
only**. That means bridge → catalog → runtime, for one allowed call. It is
never stored, logged, or audited on the way, and refresh tokens never leave
the bridge. This amends this contract's earlier statement that the token
never transits the catalog. Shared-secret values (path 1) still never enter
the control plane.

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
- **How the token is fetched:** the runtime sends only the chat identity
  (`--provider-user`) or `--user`. The catalog resolves the invoking Kei user,
  then fetches that user's row from the bridge (path 2, step 2). The harness
  cannot name another user's token.
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
  409, deletes the row, and the catalog denies `oauth_reconnect_required`.
  Suspending the connector in the catalog denies every user.
- **Audit:** `credential_subject = kei_user_id` and
  `account_email_digest`. The raw email never appears in audit.
- **Supported today:** the token row, its binding, `UNIQUE(user_id, provider)`,
  the connect flow, revoke, and the secret-authenticated relay the catalog
  calls. **New:** the `account_email` column and digest; `account_model` on
  the connector; a per-user
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
  stored as `user_id = subject = connector:<connector_id>` (a service subject,
  not the admin who connected it), bound to tenant/workspace, with the
  connector's unique `credential_ref`.
- **How the token is fetched:** the catalog fetches the `connector:<id>` row
  (path 2, step 2) for any invoking user the policy allows.
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
- **Audit:** `credential_subject = connector:<id>`. `impersonate_email` is
  admin-set connector config, so it is already visible to admins in the
  connector's settings.
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

**Decision D5.** The consented email is stored on the bridge token row, and
audit uses:

`account_email_digest = "hmac-sha256:" + hex(HMAC-SHA256(k_tenant, lower(trim(email))))`

where `k_tenant = HMAC-SHA256(k_bridge, tenant_id)` and `k_bridge` is a key
held only by the bridge. The bridge computes the digest and returns it on the
relay response, so the raw email never reaches the catalog or the runtime.
The digest is stable within a tenant, so an auditor can tell whether two calls
used the same account, but a dictionary attack outside Kei cannot reverse it.
Until the bridge ships the column and the digest, `account_email_digest` is
absent, and audit records the credential subject only. For delegation (c),
the runtime cannot hold `k_bridge`, so it records `credential_subject` only
and no email digest.

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
| google_drive | `docs.read` | `drive/<drive_id>/files/<file_id>` | `{}` | `{file_id, text}`, with `text` capped at 256 KiB (a larger document is `result_too_large`) |
| linear | `issue.read` | `linear/issue/<id>` | `{}` | `{id, identifier, team_key, project_id?, title, state}` |
| linear | `team.read` / `project.read` / `cycle.read` | `linear/team/<key>` / `linear/project/<id>` / `linear/cycle/<id>` | `{}` | the provider's typed struct |
| github | `repository.read`, `issue.read`, `pull_request.read`, `check.read`, `workflow.read` | existing contract resources | `{}` | the provider's typed struct |
| tito | `event.list` | `tito/<account>/events` | `{status?: upcoming (default) \| past \| archived, page?: ≥1}` | `{events: [TitoEvent], next_page?}` |
| tito | `event.get` | `tito/<account>/events/<event>` | `{}` | `TitoEvent` |
| tito | `release.list` | `tito/<account>/events/<event>/releases` | `{}` | `[TitoRelease]` |
| tito | `ticket.summary` | `tito/<account>/events/<event>/ticket-summary` | `{}` | `{account_slug, event_slug, total, by_state, by_release}`; fails closed above 5000 tickets |
| crm | `lead.read` | `leads`, `leads/<id>`, `customers`, `customers/<id>` | `{}` | `{records: [Lead]}` or `{record: Lead}` |
| http_api | `http.get`, `http.head` | the request path | `{path: string (relative, must match allowed_path_patterns), query?: {name: [values]} (names must be in query_allowlist)}` | `{status_code, headers, body}`, with headers and JSON fields redacted per the connector's `redaction` rules and the body capped at `response_max_bytes` |

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

`http_api` (D4) is the existing `ExecuteHTTP` path (`http_runtime.go`): one
allow-listed base URL per connector, a shared-secret key injected into the
configured header or query parameter, SSRF checks on the resolved addresses,
a same-host redirect policy, a timeout, and a response-size limit. It returns
redacted bytes rather than a typed struct, so it is the one capability whose
result is not re-encoded. The connector's `redaction` rules are its
allowlist. MarketingSite's `/api/leads` (key only) is reached through
`http_api`, not through `crm`.

### CRM service assertion (D3: signed by the runtime)

The CRM Worker (`POST /api/crm/v1/invoke`) needs two credentials on every
call:

1. `X-KEI-API-Key`: the Worker's `CRM_CONNECTOR_API_KEY` (path 1, per
   connector).
2. `Authorization: Bearer <assertion>`: an ES256 JWT that **the runtime
   signs** with its own per-installation key, after the catalog allows the
   call.

The assertion:

- Header `{alg: ES256, typ: JWT, kid: <installation key id>}`.
- Claims are the Worker's `claimsSchema`: `iss = kei-runtime:<installation_id>`,
  `aud` = the connector's `assertion_audience`, `iat`, `exp = iat + 60s`
  (inside the Worker's max age), a random `jti` (the Worker consumes it once),
  plus tenant, workspace, subject, agent, connector (all from the
  catalog-minted envelope, never from harness input), `provider=crm`,
  `connector_status`, `capabilities`, `policy`, `capability`, `action`,
  `resource`, `trace_id`, and the optional `idempotency_key` and
  `approval_id`.
- `capabilities` must carry the Worker's fixed `requires_approval` values
  (`lead.read` false; `lead.create` and `lead.update` true), because the
  Worker rejects any mismatch. `policy.allowed_actions` and
  `policy.allowed_resources` come from the connector's descriptor. The Worker
  denies an empty list, so a `crm` connector must set them (section 9).
- The runtime sends `{"data": <input.data>}` as the body. A Worker 401 or 403
  maps to `provider_denied`.

**Key provisioning (part of runtime setup, HAI-222):**

- Each runtime installation has one ES256 (P-256) signing key. It is generated
  on the tenant side during setup and stored in the tenant's secret manager.
  Neither Kei nor the catalog ever sees the private key. The runtime reads it
  with the same `SecretStore`, configured by
  `KEI_SERVICE_ASSERTION_KEY_BACKEND`, `KEI_SERVICE_ASSERTION_KEY_REF` (the
  PEM private key), and `KEI_SERVICE_ASSERTION_KID`, formatted
  `kei-rt-<installation_id>-<n>`.
- Setup exports the public key as a JWK and registers it with the Worker,
  together with the installation's `installation_id`, `tenant_id`, and
  `workspace_id`.
- A runtime without a signing key configured denies `crm` calls with
  `assertion_key_unavailable`. Other providers are unaffected.

**Worker change (separate MarketingSite ticket):** replace the single
`KEI_SERVICE_ASSERTION_PUBLIC_KEY` with a key list,
`KEI_SERVICE_ASSERTION_PUBLIC_KEYS`, as JSON or a JWKS URL:
`{keys: [{kid, kty: "EC", crv: "P-256", x, y, alg: "ES256", installation_id,
tenant_id, workspace_id, status: "active" | "retiring"}], revoked_kids: []}`.
The Worker must:

- require `kid` and pick the key by it; an unknown or revoked `kid` is 401;
- require `iss == kei-runtime:<the key's installation_id>`;
- require the claims' tenant and workspace to equal the key's, otherwise 403,
  so one installation's key cannot assert for another tenant;
- keep the existing `jti` replay check, the idempotency check, and the D1
  approval gate.

**Rotation:** generate a new key, add it to the Worker list as `active`,
switch the runtime to the new ref and kid, mark the old key `retiring`, and
remove it after the assertion max age (300s) has passed. **Revocation:** add
the `kid` to `revoked_kids` (effective immediately), then delete the secret.

**Residual risk (accepted with D3):** the Worker can no longer verify that
the catalog allowed the call, because the runtime signs its own assertion.
A compromised runtime holding both its signing key and the connector's API
key can call the CRM within its own tenant and workspace without a catalog
decision. The kid → tenant/workspace binding bounds that exposure, writes
still need a Worker-side approval, and the catalog's decision record (joined
on `trace_id`) makes an unaudited call detectable.

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

### Runtime layout

In `kei-connector-runtime`, connector code lives under `internal/connector`:
`invoke` (the command, the catalog call, execution dispatch, and audit),
`input` (input parsing and per-capability validation), `credentials` (the two
credential paths), and one package per connector: `gmail`, `googledrive`,
`linear`, `github`, `tito`, `crm` (the MarketingSite Worker client and the D3
assertion signing), and `httpapi` (the governed HTTP executor). Each connector
package wraps its `kei-connector-contracts/providers` client and applies that
connector's redaction.

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
| `oauth_not_connected` | The catalog got a bridge 404: no token row for the binding |
| `oauth_reconnect_required` | The catalog got a bridge 409: refresh failed, or the token expired with no refresh token (row deleted) |
| `oauth_binding_mismatch` | The catalog got a bridge 403: the row is bound to another tenant, workspace, or subject |
| `oauth_bridge_unavailable` | The bridge is unreachable or returns 5xx. This is **not** mapped to enrollment, unlike the legacy `authorize` path. |
| `oauth_token_expired` | The `oauth` block is past `expires_at` when the runtime would use it |
| `insecure_transport` | An `oauth` block arrived over non-TLS HTTP to a non-loopback host |
| `assertion_key_unavailable` | A `crm` call with no installation signing key configured, or the key failed to load or parse |
| `provider_denied` | Provider 401 or 403 |
| `provider_not_found` | Provider 404 |
| `provider_rate_limited` | Provider 429 |
| `provider_error` | Other provider failure; only the status class is recorded |
| `provider_timeout` | Provider deadline exceeded |
| `result_too_large` | Raw provider response over 4 MiB, or redacted result over 1 MiB |
| `capability_not_supported` | The capability's action is not `read`. Writes are a later layer (section 10). |
| `account_model_not_supported` | `domain_delegation`: the account model is defined but not executed yet (follow-up) |

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
2. **Execution:** the runtime appends it to the `KEI_PROXY_AUDIT` JSONL. Until
   the catalog accepts a `connector_execution` record (follow-up), it is
   written as a decision-class line that the existing `collector` flush ships:
   `span_id` is a new id, `parent_span` is the call's `trace_id`, `tool_name`
   is `connector:<provider>:<capability>`, `tool_args_digest` is
   `input_digest`, and `policy_reason` is the `reason_code` (or `executed`).
   The execution fields below stay in the local spool until then. It carries
   `span_id` (= `trace_id`), `invoked_at`, `org_id`, `workspace_id`,
   `agent_id`, `invoking_subject`, `connector_id`, `provider`, `capability`,
   `action`, `resource`, `credential_source`, `account_model`,
   `credential_subject` (Kei user id, or `connector:<id>`),
   `account_email_digest` (OAuth only, when the bridge supplies it),
   `assertion_kid` (crm only), `input_digest`,
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
| crm | shared secret | `base_url` (https, the MarketingSite origin; no userinfo, query, or fragment; host must resolve to a public address), `assertion_audience` (must equal the Worker's `KEI_SERVICE_ASSERTION_AUDIENCE`), `allowed_actions` (default `["read"]`), `allowed_resources` (default `["leads", "customers"]`) | `api_key` (≥ 32 chars, the Worker's `CRM_CONNECTOR_API_KEY`) |
| http_api | shared secret | the existing `http_api` block: `registered_base_url` (https, one host), `allowed_methods` (`GET`/`HEAD`), `allowed_path_patterns`, `query_allowlist`, `credential_injection` (`location` header or query, `name`, optional `scheme`), `timeout_ms`, `response_max_bytes`, redirect policy, `redaction` | the injected key |

The CRM assertion signing key is per **installation**, not per connector, so it
is not a connector setup field. Runtime setup (HAI-222) provisions it
(section 5).

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
  ship. With D3 the assertion is runtime-signed, so the Worker cannot take the
  catalog's approval on trust; the likely direction is to sync the catalog's
  approval into the Worker's store. It is tracked as a follow-up, not decided
  here.

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
  "oauth": {                        // allow + credential_source=oauth only
    "access_token": "…",
    "token_type": "Bearer",
    "expires_at": "2026-09-28T20:00:00Z",   // use-by, ≤ now + 60s
    "account_email_digest": "hmac-sha256:…" // when the bridge supplies it
  }
}
```

The `connector` descriptor is the connector's full non-secret metadata (the
`kei-connector-contracts` `contract.Metadata` shape, including `name`,
`scopes`, `capabilities`, `policy`, `config`, and `created_by`) plus
`credential_backend`, because the provider clients re-run `ValidateCall` over
it. The runtime validates it with `setup.ValidateMetadata`.

A deny response gains `reason_code` (section 7) and never carries `oauth`.
The invoke handler sets `Cache-Control: no-store` and never logs the
response body. The token is not copied into `envelope`, `audit_record`, or
`audit_records`.

The request gains `provider_user_id` (chat identity; resolved to the Kei user
through `chat_identities`, with `enrollment_required` when unlinked, as
`authorize` does) and `input_digest`. Descriptor field names avoid the
substring `secret` because of the API redaction guard.

The catalog reads the bridge relay with the bridge secret, which already
exists in the control plane, so no new bridge endpoint is needed. The bridge
changes (the `account_email` column and digest, the per-user and shared row
keys, and the `connector_provider` state fix) are a separate `kei` stack.
Layer 2 runs against a fake catalog until layer 3 lands.

## Decisions

Settled by the user on 2026-09-28:

- **PDE Gmail account model:** per-user (section 4a), the default for chat
  harnesses.
- **D1 (provider code home):** `kei-connector-contracts` v0.2.0, with the
  catalog's gmail/tito providers and the credential-source fields; released
  first, then imported by the runtime. Moving the catalog onto the module is a
  follow-up.
- **D2 (OAuth token delivery):** the catalog proxies the token from the
  bridge on an allowed invoke, for that call only (section 3, path 2).
- **D3 (CRM assertion):** the runtime signs it with its own per-installation
  ES256 key from the tenant secret manager; the Worker trusts a key list with
  rotation and revocation (section 5).
- **D4 (`http_api`):** kept as a generic governed connector with one
  allow-listed base URL and a shared-secret key.
- **D5 (account email):** stored on the bridge token row; audited as a
  per-tenant HMAC digest (section 4).

### Cross-repo follow-ups

| Repo | Work |
| --- | --- |
| `kei` (oidc-bridge) | `account_email` column (field-encrypted) populated at connect; per-tenant HMAC digest on the relay response; shared-model rows keyed `connector:<id>`; widen the unique key to `(user_id, provider, tenant_id, workspace_id)`; persist `connector_provider` in `oauth_states` (Gmail callback bug) |
| MarketingSite | `KEI_SERVICE_ASSERTION_PUBLIC_KEYS` key list or JWKS; kid → installation/tenant/workspace binding; `iss = kei-runtime:<installation_id>`; `revoked_kids`; later, approval sync for CRM writes |
| `kei-policy-catalog` | Import `kei-connector-contracts` v0.2.0 and delete the in-tree `pkg/connectors` fork; stop allowing new `s3` connectors |
| `kei-policy-catalog` (layer 3) | Connector descriptor, `account_model`/`config` columns, token proxy on allow, `provider_user_id`, `input_digest`, `reason_code` |
| Runtime setup (HAI-222) | Generate and store the per-installation assertion key; export its JWK for the Worker |
| CLI and web UI setup | Render `kei.connector-setup/v1`; seal secret fields to the installation's credential-sync key |
