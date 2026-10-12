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
| `notion` | shared secret (path 1): a Notion internal integration token | n/a | supported (HAI-216); OAuth is not offered |
| `discord` | shared secret (path 1): a Discord bot token | n/a | supported (HAI-310); OAuth is not offered |
| `grafana` | shared secret (path 1): a Grafana service-account token, against the connector's `grafana.base_url` (`Metadata.Grafana`) | n/a | supported (HAI-311); OAuth is not offered |
| `skills_repo` | OAuth token proxied by the catalog (path 2): the invoking user's GitHub token; or shared secret (path 1): a GitHub token with read access to the repository's contents | per-user (oauth); n/a (opaque_ref) | supported (HAI-431): reads a workspace's agent skills from a GitHub repository |
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
                                                                 
                                                                on allow for OAuth:
                                                                GET bridge token ──► oidc-bridge
     ◄──── allow + connector descriptor                         (bridge secret stays
           + oauth {access_token, expires_at} (OAuth only)      in the control plane)
  4. resolve the credential
       path 1: secrets.Store.Get(credential_backend, credential_ref)
       path 2: use the oauth access token from step 3 (this call only)
       crm:    also sign the service assertion with the installation key (D3)
  5. execute the provider call                   (contracts/providers client)
  6. redact the result per capability           (typed allowlist, size cap)
  7. emit the audit event                        (digests only, section 8)
  8. write the result JSON to stdout, exit 0
```

Rules:

- The input never leaves the runtime. The catalog gets only `input_digest`, so
   it can bind the decision to the exact input without seeing
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
  the OAuth token is online by design.
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
  --idempotency-key <key>      required for non-read capabilities
  --timeout <seconds>          whole-call deadline, default 30
```

The existing identity-propagation flags and variables (`--trace-id` /
`KEI_PROXY_SPAN_ID`, `--framework`) are unchanged.
`--invoking-subject` has been removed — subject is obtained from the
runtime session only.
`KEI_RUNTIME_TOKEN` comes from the environment only.

### Secrets never leave the runtime via the CLI

No `kei-proxy` command, flag, or log prints, echoes, exports, or returns a
resolved credential value. There is no `--show`, `--reveal`, or `--debug` dump
option and no `credential get` command. With `kei-proxy run`, a resolved value
is injected only into the child process environment, and values in the child's
stdout and stderr are masked before they reach the caller. Audit records and
credential errors contain connector/reference identifiers and field names,
never values.

Debugging inside the harness is the harness developer's responsibility. Keep
credential values out of harness transcripts and logs.

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
same `connect` field is also passed through on the `authorize` path (HAI-266).
The harness must show `url` privately to the user, never in a channel and never
in a log. For compatibility, the pre-contract fields `reason` and `envelope` are
kept, and any non-zero exit is a deny.

## 3. Credential paths

The two paths are never mixed. A connector's `credential_source` selects
exactly one, and the runtime never falls back from one path to the other.

### Path 1: shared secret (`credential_source = opaque_ref`)

Used by: `tito` (API token), `notion` (the internal integration token),
`crm` (the Worker's `X-KEI-API-Key`),
`http_api` (the injected key), and Google domain-wide delegation (the
service-account key). The runtime's CRM assertion signing key (D3) is read
through the same store, but it belongs to the installation, not to a connector
(section 5).

- The connector stores only `credential_ref`, an opaque pointer that passes
  `ValidateCredentialRef`. The catalog adds `credential_backend` (one of
  `aws-secrets-manager`, `azure-key-vault`, `gcp-secret-manager`) from the
  organization's credential-store installation, the same store that model
  profiles use.
- The runtime resolves it with the same `secrets.Store` registry as the
  model-profile path (`model_invoke.go`, `internal/secrets`), using workload
  identity: `Store.Get(credential_backend, credential_ref)`.
- When the secret was delivered by Kei (HAI-262, section 9), `credential_ref`
  is its stored name, and the descriptor also carries
  `credential_secret_ref`, the backend-qualified location the runtime wrote
  (`aws-secrets-manager://<region>/<name>`,
  `https://<vault>/secrets/<name>`, or `projects/<project>/secrets/<name>`).
  The runtime reads `secrets.Store.Get(credential_backend,
  credential_secret_ref)` instead, and only when that location ends in
  `"/" + credential_ref`; any other value is `descriptor_invalid`.
- The `gcp-secret-manager` backend (HAI-268) reads the latest version of the
  named secret through the pod's workload identity (Application Default
  Credentials); a missing secret or a missing
  `roles/secretmanager.secretAccessor` grant denies
  `credential_unavailable` or `credential_backend_unavailable` respectively.
- The secret value never enters the catalog, the invoke response, or audit.
  Setup writes it through sealed credential delivery (section 9).

### Path 2: user-delegated OAuth (`credential_source = oauth`)

Used by: `gmail`, `google_drive`, `linear`, `github` (per-user and shared
account models).

**Decision D2: the catalog proxies the token.** The runtime never calls the
bridge and never holds `OIDC_BRIDGE_SECRET` (ADR-020).

1. The catalog finishes the whole decision first: structure, agent binding,
   ABAC policy, then `setup.ValidateMetadata` over the
   descriptor. Only when the final decision is `allow`, and only for a
   connector with `credential_source=oauth`, does it fetch a token, for that
   decision's (invoking Kei user, connector, capability).
2. **TLS first.** The catalog fetches a token only for a caller that reached
   it over TLS: `r.TLS` is set, `X-Forwarded-Proto` is `https`, or the caller
   is loopback with no `X-Forwarded-For`. Otherwise it denies
   `insecure_transport` before calling the bridge.
3. **Who the token belongs to.** The binding comes from the account model
   (section 4):
   - **per-user:** `user_id = subject = <invoking Kei user id>`. The invoking
     subject must be a Kei user id that is a member of the connector's
     workspace. Otherwise the catalog denies `policy_deny` and never calls the
     bridge. Agent ids and email-address subjects never fetch a token.
   - **shared:** `user_id = subject = connector:<connector_id>`.
   - **legacy oauth** (no account model): the connector's declared subject.
4. The catalog calls the existing bridge relay server to server, with the
   bridge secret (`OIDC_BRIDGE_SECRET`), which stays in the control plane:
   `GET {OIDC_BRIDGE_URL}/oauth/credentials/{user_id}/{provider}?tenant_id=…&workspace_id=…&subject=…`.
   The bridge checks the binding (403 on mismatch) and refreshes an expired
   token.
5. **The catalog checks the bridge's answer too.** It rejects a relay
   response whose echoed `tenant_id`, `workspace_id`, or `subject` differs
   from the binding it asked for (`oauth_binding_mismatch`). A legacy
   *unbound* bridge row echoes an empty binding, so it also denies
   `oauth_binding_mismatch`. There is no legacy fallback: per-user rows must be
   connected with a binding whose subject is the Kei user id.
6. The catalog returns the token in the invoke response, under
   `oauth: {access_token, token_type, expires_at, account_email_digest?}`
   (section 11).
7. The runtime uses the token for this one provider call and then drops it.

**Scope of the token.** The catalog fetches it per call, after the (user,
connector, capability) decision, and the runtime may use it for at most 60
seconds. It is still the user's **provider-wide grant**: a Gmail token carries
the full `gmail.readonly` scope the user consented to, not a token narrowed to
this capability or resource. The bridge cannot mint narrower tokens.
Narrowing happens around the token: the catalog's decision, the runtime's
fixed capability-to-endpoint mapping, and the redaction in each connector
package.

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
- **TLS only, enforced on both sides:** the catalog refuses to fetch a token
  for a non-TLS caller (step 2) and sets `Cache-Control: no-store` on every
  invoke response. The runtime refuses an `oauth` block it received over
  plain HTTP, unless the control-plane host is loopback (for local tests).
  Both deny `insecure_transport`. This means local compose
  (`host.docker.internal` over http) cannot run OAuth connectors.
- **Only on a matching allow:** a deny response never carries `oauth`. The
  runtime checks that `oauth` is present exactly when the descriptor says
  `credential_source=oauth`, and that the descriptor's connector and
  capability equal the request's; any mismatch is `descriptor_invalid`.
- **Bridge failures become catalog denies** (section 7): bridge 404 →
  `oauth_not_connected`; 409 → `oauth_reconnect_required`; 403, or an echoed
  binding that doesn't match → `oauth_binding_mismatch`; unreachable, 5xx,
  401, a malformed relay response, or a catalog without `OIDC_BRIDGE_URL`/
  `OIDC_BRIDGE_SECRET` → `oauth_bridge_unavailable`. None of them falls back
  to another credential.

ADR-011 note: the OAuth access token moves bridge → catalog → runtime **in
memory**, for one allowed call. The catalog fetches it only after the final
allow, only for `credential_source=oauth`, and only for a TLS caller, and it
never stores, logs, or audits it. The runtime uses it for one provider call.
Refresh tokens never leave the bridge. Shared-secret values (path 1) never
enter the control plane. This amends this contract's earlier statement that
the token never transits the catalog.

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
  `credential_source = oauth`. The binding is required: the catalog denies a
  legacy unbound row with `oauth_binding_mismatch` (section 3, step 5), so a
  user connected before bindings existed must reconnect.
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
- **What the runtime does:** it resolves the key through `secrets.Store`, signs
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
| skills_repo | yes | no | no | per_user |

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
| google_drive | `drive.search` (used by the existing `drive.list_files` tool) | `drive/<drive_id>` | `{query?: string ≤512, mime_type?: valid MIME type, limit?: 1..100 (default 50)}` | `[{id, drive_id, name, mime_type, modified_at}]`; only the first Google Drive `files.list` page (provider default page size), `trashed=false`, scoped to the bound drive; MIME filtering and output limit apply within that page. The existing tool schema has no cursor, so it cannot request subsequent pages. |
| google_drive | `drive.metadata.read` | `drive/<drive_id>/files/<file_id>` | `{}` | `{id, drive_id, name, mime_type, modified_at}` |
| google_drive | `docs.read` | `drive/<drive_id>/files/<file_id>` | `{}` | `{file_id, text}`, with `text` capped at 256 KiB (a larger document is `result_too_large`) |
| linear | `issue.read` | `linear/issue/<id>` | `{}` | `{id, identifier, team_key, project_id?, title, state}` |
| linear | `team.read` / `project.read` / `cycle.read` | `linear/team/<key>` / `linear/project/<id>` / `linear/cycle/<id>` | `{}` | the provider's typed struct |
| github | `repository.read`, `issue.read`, `pull_request.read`, `check.read`, `workflow.read` | existing contract resources | `{}` | the provider's typed struct |
| tito | `event.list` | `tito/<account>/events` | `{status?: upcoming (default) \| past \| archived, page?: ≥1}` | `{events: [TitoEvent], next_page?}` |
| tito | `event.get` | `tito/<account>/events/<event>` | `{}` | `TitoEvent` |
| tito | `release.list` | `tito/<account>/events/<event>/releases` | `{}` | `[TitoRelease]` |
| tito | `ticket.summary` | `tito/<account>/events/<event>/ticket-summary` | `{}` | `{account_slug, event_slug, total, by_state, by_release}`; fails closed above 5000 tickets |
| notion | `search` | `search` (exactly; the `search/<query>` form is refused, so the query never reaches the catalog) | `{query?: string ≤512, page_size?: 1..25 (default 10)}` | `{results: [NotionItem], has_more, next_cursor?}`; an empty query lists what the integration can see |
| notion | `page.read` | `pages/<id>` (32 hex digits, bare or dashed) | `{}` | `NotionPage` |
| notion | `database.query` | `databases/<id>` | `{page_size?: 1..25 (default 10)}`; filters and sorts are not accepted yet | `[NotionPage]` |
| discord | `guild.list` | `guilds` | `{limit?: 1..100 (default 25), after?: snowflake}` | `{guilds: [{id, name, owner}], next_after?}`; `next_after` is set when the page is full |
| discord | `guild.read` | `guilds/<snowflake>` | `{}` | `{id, name, description?, owner_id, member_count}` |
| discord | `channel.list` / `role.list` | `guilds/<snowflake>/channels` / `guilds/<snowflake>/roles` | `{}` | `[DiscordChannel]` / `[{id, name, position, permissions, managed}]` |
| discord | `channel.read` | `channels/<snowflake>` | `{}` | `DiscordChannel` |
| discord | `thread.list` | `channels/<snowflake>/threads` | `{}` | `[{id, guild_id, parent_id, name, type, message_count, archived}]`: the channel's active threads |
| discord | `message.list` | `channels/<snowflake>/messages` | `{limit?: 1..100 (default 25), before?: snowflake, after?: snowflake}` (at most one cursor) | `{messages: [DiscordMessage], next_before?, next_after?}`; the cursor is set when the page is full |
| discord | `message.read` | `channels/<snowflake>/messages/<snowflake>` | `{}` | `DiscordMessage` |
| grafana | `folder.list` | `folders` | `{limit?: 1..100 (default 25), page?: ≥1 (default 1)}` | `{folders: [GrafanaFolder], next_page?}`; `next_page` is set when the page is full |
| grafana | `folder.read` | `folders/<uid>` | `{}` | `GrafanaFolder` |
| grafana | `dashboard.search` | `search` (exactly; the query stays in the input) | `{query?: ≤256 chars, tags?: ≤10 of 1..64 chars, limit?: 1..100 (default 25), page?: ≥1}` | `{dashboards: [{uid, title, url, tags, folder_uid?, folder_title?}], next_page?}`; dashboards only |
| grafana | `dashboard.read` | `dashboards/<uid>` | `{}` | `{uid, title, tags, folder_uid?, version, panels: [{id, title, type, datasource_uid?, queries?}]}` |
| grafana | `datasource.list` / `datasource.read` | `datasources` / `datasources/<uid>` | `{}` | `[GrafanaDatasource]` / `GrafanaDatasource` |
| grafana | `alert_rule.list` | `alert_rules` | `{}` | `{rules: [{uid, title, folder_uid, rule_group, labels?, paused}], truncated}`; at most 200 rules |
| grafana | `annotation.list` | `annotations` | `{from?, to?: epoch ms, set together, to > from, ≤30 days apart (default the last 24h), dashboard_uid?: uid, tags?: ≤10, limit?: 1..100 (default 25)}` | `[{id, dashboard_uid?, panel_id?, time, time_end?, text, tags?}]` |
| grafana | `datasource.query` | `datasources/<uid>/query` | `{expr: string 1..4096, from?, to?: epoch ms, set together, to > from, ≤7 days apart (default the last hour), max_rows?: 1..1000 (default 100)}` | `{frames: [{name?, fields: [{name, type?, labels?}], rows}], truncated}`; at most `max_rows` rows across all frames |
| crm | `lead.read` | `leads`, `leads/<id>`, `customers`, `customers/<id>` | `{}` | `{records: [Lead]}` or `{record: Lead}` |
| crm | `investor.list` (HAI-210) | `investors` | `{stage?: prospect \| contacted \| meeting \| diligence \| committed \| passed, q?: ≤200 chars, limit?: 1-100 (default 20), cursor?: ≤128 chars}`, sent to the Worker as `{"data": <input>}` | `{records: [Investor], next_cursor: string \| null, has_more}` |
| crm | `investor.read` (HAI-210) | `investors/<id>` | `{}` | `{record: Investor}` |
| skills_repo | `skills.list` | `skills` | `{}` | `{ref, commit, skills: [{name, version?, description?, harnesses, path}]}`; at most 500 skills, read from the connector's `config` (`repo_url`, `ref`, `subdirectory`) |
| skills_repo | `skills.fetch` | `skills/<name>` (one segment of letters, digits, `-`, `_`; anything else is `input_invalid` before any provider call) | `{}` | `{skill, commit, format: "tar+gzip", digest: "sha256:<hex>", size, archive}`; `archive` is the base64 encoded skill folder, at most 8 MiB, and must match `size` and `digest` or the call fails closed. Its result limit is the archive bound, not 1 MiB |
| http_api | `http.get`, `http.head` | the exact request path, e.g. `/contacts/1` (no query) | `{path: string (must equal the resource exactly), query?: {name: [values]} (names must be in query_allowlist)}` | `{status_code, headers, body}`, with headers and JSON fields redacted per the connector's `redaction` rules and the body capped at `response_max_bytes` |

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
- **Notion:** titles and metadata only. A `NotionItem` is `{object: page |
  database, id, title, url, parent_type?, parent_id?, created_at, updated_at,
  archived}`; a `NotionPage` is the same without `object`. Property values
  (people, emails, rich text, numbers, and so on) are dropped when the
  provider response is decoded, and page block content is never fetched. No
  policy attribute opts in to more yet; adding one (like
  `gmail_include_body`) is a contract change. The runtime calls
  `api.notion.com/v1` with `Notion-Version: 2022-06-28`, and a connector
  whose `credential_source` is not `opaque_ref` is `descriptor_invalid`.
- **Discord:** a `DiscordMessage` is `{id, channel_id, type, content, author:
  {id, username, bot}, timestamp, edited_at?, attachment_count,
  reaction_count}`. Attachments (and their CDN URLs), embeds, mentions, and
  every other user field (email, avatar, and so on) are dropped when the
  response is decoded. A `DiscordChannel` is `{id, guild_id?, name, type,
  position, parent_id?, topic?, last_message_id?}`; permission overwrites are
  dropped. Guild members are not readable. A snowflake is 17 to 20 digits;
  any other resource shape is `input_invalid` before a request. The runtime
  calls `discord.com/api/v10` with `Authorization: Bot <token>`, and a
  connector whose `credential_source` is not `opaque_ref` is
  `descriptor_invalid`. `thread.list` makes two requests: the channel (for its
  guild) and the guild's active threads, filtered to the channel.
- **Grafana:** a `GrafanaFolder` is `{uid, title, url?, parent_uid?}` and a
  `GrafanaDatasource` is `{uid, name, type, is_default}`: a datasource's URL,
  user, database, JSON settings, and secure-field flags are never returned.
  Dashboards return a panel summary only (a collapsed row's panels follow the
  row), with at most 10 query expressions per panel; templating values,
  links, and the rest of the dashboard model are dropped. Annotations,
  folders, and alert rules drop who created them (logins, emails, avatars),
  and alert rules drop their queries and annotations. A uid is 1 to 40 of
  `[A-Za-z0-9_-]`; any other resource shape is `input_invalid` before a
  request. The runtime sends `Authorization: Bearer <token>` to
  `grafana.base_url`, and a connector whose
  `credential_source` is not `opaque_ref` is `descriptor_invalid`.
- **Grafana host (`descriptor_invalid` before any request):** `base_url` must
  be an `https` origin, with no path, query, fragment, or userinfo
  (`contract.GrafanaConfig.Validate`). Self-hosted Grafana is
  usually internal, so unlike `http_api`, private, CGNAT, and loopback
  addresses are allowed. Link-local addresses (IPv4 and IPv6), unspecified and
  multicast addresses, the cloud metadata addresses outside link-local
  (`fd00:ec2::254`, `100.100.100.200`), and metadata host names
  (`metadata.google.internal` and similar) are always refused. The host is
  checked as an IP literal or on every resolved address. Redirects are never
  followed, so the token cannot be carried to a host the check did not see.
- **Grafana queries:** `datasource.query` first reads the datasource and
  runs only against `prometheus` or `loki`, whose query languages cannot
  write. Any other type (SQL, InfluxDB, Elasticsearch, and so on) is
  `input_invalid`, and no query is sent. The query goes to `POST /api/ds/query`
  with `maxDataPoints = max_rows`, `intervalMs = max(range / max_rows, 1s)`,
  and, for Loki, `maxLines = max_rows`. The runtime also enforces the row cap
  on the response. A per-query error is `provider_error`, and its text is
  never surfaced. The expression stays in the input, so the catalog and audit
  see only its digest.
- **CRM:** a Lead is `{id, company_name, contact_name, email, role, status,
  priority, source, tier, created_at, updated_at}`. Free text (`message`,
  `early_access_notes`, audit answers) is dropped even if the Worker returns
  it. An
  Investor is `{id, name, firm, email, stage, created_at, updated_at}`; any
  other field the Worker returns is dropped.

`http_api` (D4) is the existing `ExecuteHTTP` path
(`internal/connector/httpapi`): one
allow-listed base URL per connector, a shared-secret key injected into the
configured header or query parameter, SSRF checks on the resolved addresses,
a same-host redirect policy, a timeout, and a response-size limit. It returns
redacted bytes rather than a typed struct, so it is the one capability whose
result is not re-encoded. The connector's `redaction` rules are its
allowlist. MarketingSite's `/api/leads` (key only) is reached through
`http_api`, not through `crm`.

**The http_api resource is the request.** Its resource is the exact request
path, with no query string, and that is what policy authorizes. The catalog
checks the resource against the connector's `allowed_path_patterns`. The
runtime then requires `input.path == resource` exactly, before any
credential is fetched. Both must be a plain absolute path: a leading `/`, no
`?`, `#`, or backslash, no `.` or `..` segment, no percent-encoded dot,
slash, or backslash, and no scheme or host. Nothing is normalized, and any
difference denies `input_invalid`. Without this, an allow for `/contacts/1`
could be used to read `/contacts/999` (HAI-256). Query parameters travel
separately in `input.query` and are limited to `query_allowlist`.

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
 `resource`, `trace_id`, and `idempotency_key`.
- `policy.allowed_actions` and
  `policy.allowed_resources` come from the connector's descriptor. The Worker
  denies an empty list, so a `crm` connector must set them (section 9).
- The runtime sends `{"data": <input.data>}` as the body. A Worker 401 or 403
  maps to `provider_denied`.

**Key provisioning (part of runtime setup, HAI-222):**

- Each runtime installation has one ES256 (P-256) signing key. It is generated
  on the tenant side during setup and stored in the tenant's secret manager.
  Neither Kei nor the catalog ever sees the private key. The runtime reads it
  with the same `secrets.Store`, configured by
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
- keep the existing `jti` replay check and the idempotency check.

**Rotation:** generate a new key, add it to the Worker list as `active`,
switch the runtime to the new ref and kid, mark the old key `retiring`, and
remove it after the assertion max age (300s) has passed. **Revocation:** add
the `kid` to `revoked_kids` (effective immediately), then delete the secret.

**Residual risk (accepted with D3):** the Worker can no longer verify that
the catalog allowed the call, because the runtime signs its own assertion.
A compromised runtime holding both its signing key and the connector's API
key can call the CRM within its own tenant and workspace without a catalog
decision. The kid → tenant/workspace binding bounds that exposure, writes
and the catalog's decision record (joined
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
`linear`, `github`, `tito`, `discord` and `grafana` (HTTP clients, called
after the contract's `providers.Guard`), `notion` (the Notion REST backend behind the
contract's `providers.NotionBackend` seam, since the module has only an
in-memory one), `crm` (the MarketingSite Worker client and the D3
assertion signing), `httpapi` (the governed HTTP executor), and
`skillsrepo` (the contract's skills repository client and GitHub backend,
plus the archive digest and size check). Each connector
package wraps its `kei-connector-contracts/providers` client and applies that
connector's redaction.

Every adapter is compiled into every `kei-proxy` binary. That is known tech
debt (HAI-320): see [tech-debt.md](tech-debt.md) for the measurement, the
options, and the interim rule (no heavy SDKs in adapters; use `net/http`).

## 7. Errors and fail-closed rules

Every row denies (exit 1) and returns no result data. "Catalog" codes arrive
in the invoke response's `reason_code` and the runtime passes them through
unchanged. "Runtime" codes are decided locally. A catalog deny without a
`reason_code` (an older catalog) is classified by the runtime as
`enrollment_required` when it carries `enrollment`, and `policy_deny` otherwise.

| reason_code | Emitted by | When |
| --- | --- | --- |
| `input_invalid` | runtime | Input fails the capability schema, is over 16 KiB, or is not JSON |
| `catalog_unavailable` | runtime | The catalog is unreachable, returns non-200, or returns a malformed body |
| `policy_deny` | catalog | Structure, agent binding, or ABAC policy denies; or a per-user invoking subject is not a Kei user in the connector's workspace (no bridge call) |
| `enrollment_required` | catalog | The chat identity is not linked (the catalog answers `decision: "enrollment_required"`); carries `enrollment` |
| `descriptor_invalid` | both | Catalog: the descriptor fails `setup.ValidateMetadata`. Runtime: an allow without a descriptor or envelope, a descriptor that doesn't match the request or fails `setup.ValidateMetadata`, an `oauth` block on a non-OAuth connector (or none on an OAuth one), or a connector config the connector needs is missing (for example crm without `base_url`) |
| `insecure_transport` | both | Catalog: the caller is not TLS, so no token is fetched. Runtime: an `oauth` block arrived over plain HTTP from a non-loopback host |
| `oauth_not_connected` | catalog | Bridge 404: no token row for the binding |
| `oauth_reconnect_required` | catalog | Bridge 409: refresh failed, or the token expired with no refresh token (row deleted) |
| `oauth_binding_mismatch` | catalog | Bridge 403, or the relay echoed a different tenant, workspace, or subject, including a legacy unbound row |
| `oauth_bridge_unavailable` | catalog | Bridge unreachable, 5xx, 401, a malformed relay response, or the catalog has no bridge configured. This is **not** mapped to enrollment, unlike the legacy `authorize` path. |
| `oauth_token_expired` | runtime | The `oauth` block is past `expires_at` when the runtime would use it |
| `provider_not_supported` | runtime | Provider not in section 1 |
| `capability_not_supported` | runtime | The capability's action is not `read`. Writes are a later layer (section 10). |
| `account_model_not_supported` | runtime | `domain_delegation`: the account model is defined but not executed yet (follow-up) |
| `credential_backend_unavailable` | runtime | No backend in the descriptor (the org has no active credential store), or the backend is not registered in this runtime (e.g. GCP today) |
| `credential_unavailable` | runtime | Secret missing, empty, or unreadable (path 1); the reference is never echoed |
| `assertion_key_unavailable` | runtime | A `crm` call with no installation signing key configured, or the key failed to load or parse |
| `provider_denied` | runtime | Provider 401 or 403 |
| `provider_not_found` | runtime | Provider 404 |
| `provider_rate_limited` | runtime | Provider 429 |
| `provider_error` | runtime | Other provider failure; only the status class is recorded |
| `provider_timeout` | runtime | Provider deadline exceeded |
| `result_too_large` | runtime | Raw provider response over 4 MiB, or redacted result over 1 MiB (or over the connector's own limit, at most 12 MiB, where it declares one: `skills_repo` `skills.fetch` declares the 8 MiB archive bound) |

Timeouts, all inside the `--timeout` budget (default 30s): catalog 10s,
credential resolution 5s, provider 15s. Reads are not retried in layer 2,
with one deliberate exception: a Discord 429 whose `Retry-After` is at most
2s is waited out and retried, up to 3 requests in all, inside the provider
deadline (Discord rate-limits per route and expects it). A longer or missing
`Retry-After` is `provider_rate_limited` at once. Writes are never retried by the runtime (the harness retries with the same
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
   `idempotency_key`.

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
| notion | shared secret | none | `api_token` (the internal integration token). Not in `kei.connector-setup/v1` yet: `kei-connector-contracts` has no Notion setup schema, so the catalog cannot set a Notion connector up until one is added (follow-up) |
| crm | shared secret | `base_url` (https, the MarketingSite origin; no userinfo, query, or fragment; host must resolve to a public address), `assertion_audience` (must equal the Worker's `KEI_SERVICE_ASSERTION_AUDIENCE`), `allowed_actions` (default `["read"]`), `allowed_resources` (default `["leads", "customers"]`; add `investors` for `investor.list`/`investor.read`, and declare those capabilities only after the Worker serves them, because the assertion carries every declared capability and the Worker rejects unknown ones) | `api_key` (≥ 32 chars, the Worker's `CRM_CONNECTOR_API_KEY`) |
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
- **Secret fields never reach the catalog in plaintext** (HAI-262). The CLI
  or console seals the value to each eligible runtime's credential-sync key
  (`GET /api/v1/organizations/{id}/credential-store/recipients?workspace_id=`)
  with the same KMP1 envelope model profiles use, and calls
  `POST /api/v1/data-connectors/{id}:setSecret` with
  `{field, credential_store_installation_id, recipients}`. The catalog keeps
  the ciphertext only until a runtime acks, records a connector credential
  generation (each call is a rotation), and names the stored secret
  `<prefix>/connectors/<connector_id>/<field>` (AWS),
  `<prefix>-connectors-<connector_id>-<field, _ as ->` (Azure), or
  `<prefix>-connectors-<connector_id>-<field>` (GCP); that name becomes
  `credential_ref`. `kei-proxy credential sync` claims the
  `operation_kind: "connector_secret"` delivery, refuses a `secret_ref` that
  does not name that connector field, decrypts, `Put`s, validates, and acks.
  The connector stays `pending` until the ack, then becomes `active`.
  `GET /api/v1/data-connectors/{id}/secrets` shows only
  `{field, set, generation, delivered_at}`.
- **Bring your own reference:** instead of a value, an operator may enter an
  existing reference (for example `kei/prod/crm/connector-api-key`, as
  provisioned by MarketingSite's `provision-crm-connector-key.sh`). It must
  pass `ValidateCredentialRef`, and `credential sync` must check it with
  `secrets.Store.Validate` (new behavior) before the connector becomes `active`.
- Validation errors name the field and never echo a submitted value.

## 10. Writes

The runtime executes a write only where the contract's api mode lists it
(`access.APIWrite` in kei-connector-contracts): every CRM write, and Linear
`issue.create` and `comment.create`. Every other write capability (Linear
`issue.update`, GitHub mutations) is denied with `capability_not_supported`.
Drive `share` is not in the capability registry (see the HAI-207 contract gap).
Rules (updated per ADR-027, kei #671, merged):

- Both entry points apply the same gate (`prepare`). A per-user connector's
  write comes from a harness as the JSON body of the serve daemon's
  `POST /v1/connectors:invoke` on the Unix socket (ADR-034), for example
  `{"schema":"kei.connector-invoke-request/v1","connector_id":"<id>","capability":"issue.create","action":"create","resource":"linear/team/ENG","idempotency_key":"<key>","input":{"team_id":"ENG","title":"..."}}`.
  The `kei-proxy connector invoke` flags are the same call: a thin client of
  that route when `KEI_CREDENTIAL_RELEASE=identity`, otherwise the direct
  path for shared connectors.

- `--idempotency-key` is required for a Linear write (`input_invalid`
  otherwise), and the catalog envelope must carry the same key
  (`descriptor_invalid` otherwise). The contract client derives the new
  issue's or comment's Linear id from it, so a replay cannot create a
  duplicate. Per-call approval transport (`--approval-id`) has been removed
  from the runtime by ADR-027.
- The runtime never retries a write. If a Linear mutation fails, one read of
  the derived id returns an entity that a previous call already created.
- A write's resource is its parent (Haikei semantics rule), and the input's
  parent identifier must equal it:

| Provider | Capability | Resource | Input | Result |
| --- | --- | --- | --- | --- |
| linear | `issue.create` | `linear/team/<team>` | `{team_id, title, description?, priority?}`; `team_id` is the team key or UUID and equals `<team>`; title 1–256 runes on one line; description ≤ 12 KiB; priority 0–4 | `{id, identifier, team_key, url}` |
| linear | `comment.create` | `linear/issue/<issue>` | `{issue_id, body}`; `issue_id` equals `<issue>`; body ≤ 12 KiB | `{id, issue_id, url}` |

- Audit is metadata only, as for reads (section 8): `input_digest`,
  `result_digest`, `idempotency_key`, and the `connector:linear:<capability>`
  tool name. The title, description and comment body never leave the runtime
  except in the provider call.
- The connector's Linear OAuth grant needs `issues:create` / `comments:create`
  (the bridge requests `read,write,issues:create,comments:create`). When the
  connector's `scopes` are Linear OAuth scopes, a missing write scope is
  denied before the provider is called.

## 11. Catalog changes (layer 3, HAI-241)

`POST /api/v1/data-connectors/invoke` in `kei-policy-catalog` implements this
as follows. It uses the `kei-connector-contracts` v0.2.0 `contract.Metadata`
and `envelope.Envelope` types.

**Request** gains two fields:
- `provider_user_id`: the chat identity on the harness key's platform,
  resolved through `web.chat_identities` to the Kei user, who becomes the
  invoking subject. An unlinked identity gets `enrollment_required`. Combining
  it with a different `invoking_subject` or `user_id` is a 400.
- `input_digest`: accepted, but not stored yet.

**Allow** (every invoke response carries `Cache-Control: no-store`):

```jsonc
{
  "decision": "allow",
  "capability": { … }, "envelope": { … }, "audit_record": { … }, // audit never carries the token
  "connector": {                  // contract.Metadata v0.2.0 + credential_backend
    "id": "…", "tenant_id": "…", "workspace_id": "…", "name": "gmail",
    "provider": "gmail", "status": "active",
    "credential_ref": "…", "scopes": ["…"], "resources": ["…"],
    "policy": { "allowed_actions": ["read"], "allowed_resources": ["…"], "destructive_enabled": false },
    "capabilities": [{ "name": "message.search", "action": "read", "description": "" }],
    "created_by": "…", "created_at": "…", "updated_at": "…",
    "credential_source": "oauth",
    "account_model": "per_user",               // omitted when unset
    "subject": "…",                            // omitted when empty
    "credential_backend": "aws-secrets-manager", // opaque_ref only
    "credential_secret_ref": "aws-secrets-manager://us-west-2/…" // delivered secrets only (HAI-262)
  },
  "credential_subject": "<kei user id> | connector:<id> | <declared subject>",
  "oauth": {                        // credential_source=oauth only
    "access_token": "…",
    "token_type": "Bearer",
    "expires_at": "2026-09-28T20:00:00Z",   // min(provider expiry, now + 60s)
    "account_email_digest": "hmac-sha256:…" // passed through from the bridge (HAI-242), when present
  }
}
```

- `connector` is the connector's non-secret `contract.Metadata`, plus
  `credential_backend`. The provider clients re-run `ValidateCall` over it,
  and both the catalog (before allowing) and the runtime validate it with
  `setup.ValidateMetadata`.
- `credential_backend` is the org's **active** credential store backend, sent
  for `opaque_ref` connectors only. It is absent when the org has no active
  store, and the runtime then denies `credential_backend_unavailable`.
- `credential_secret_ref` is sent only when `credential_ref` is the stored
  name of a secret Kei delivered (section 3, path 1).
- `credential_subject` is `contract.CredentialSubject(meta, invocation)`.
- An allow for an `opaque_ref` connector carries no `oauth`, and the bridge
  is never called.

**Deny:** `{"decision": "deny", "reason", "reason_code", "envelope",
"audit_record"}`, with no `connector`, `credential_subject`, or `oauth`.
**Enrollment:** `{"decision": "enrollment_required", "reason",
"reason_code": "enrollment_required", "enrollment": {…}}`, with no envelope and
no token. The runtime treats every decision other than `allow` as a deny and
passes `reason_code` and `enrollment` through. The reason codes are in section
7.

**Catalog configuration:** `OIDC_BRIDGE_URL` and `OIDC_BRIDGE_SECRET` (the
`kei` Helm chart must supply both). With either unset, every OAuth invoke
denies `oauth_bridge_unavailable`.

**Known gap: `config` is not sent yet.** `abac.data_connectors` has no `config`
column, so the descriptor never carries `Metadata.Config`. Connectors that
need config deny until that lands. In particular, every `crm` allow currently
hits `connector.ErrConfig` (no `base_url` or `assertion_audience`) and denies
`descriptor_invalid`. Tracked in HAI-254.

The bridge changes (the `account_email` column and digest, and the
`connector_provider` state fix) are a separate `kei` stack (HAI-242,
HAI-244).

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
| MarketingSite | `KEI_SERVICE_ASSERTION_PUBLIC_KEYS` key list or JWKS; kid → installation/tenant/workspace binding; `iss = kei-runtime:<installation_id>`; `revoked_kids` |
| `kei-policy-catalog` | Import `kei-connector-contracts` v0.2.0 and delete the in-tree `pkg/connectors` fork; stop allowing new `s3` connectors |
| `kei-policy-catalog` (layer 3) | Done in HAI-241: descriptor, `account_model` column, token proxy on allow, `provider_user_id`, `reason_code`. Open: the `config` column (HAI-254) and storing `input_digest` |
| `kei-connector-contracts` (HAI-216) | A Notion setup schema (shared secret, `api_token`); optionally move the Notion REST backend from the runtime into the module |
| `pde-harness` (HAI-216) | `notion_search` must send `--resource search` (not `notion/workspace`) and the query as `--input '{"query": …}'`; today it passes no input |
| Runtime setup (HAI-222) | Generate and store the per-installation assertion key; export its JWK for the Worker |
| CLI and web UI setup | Render `kei.connector-setup/v1`; seal secret fields to the installation's credential-sync key |
