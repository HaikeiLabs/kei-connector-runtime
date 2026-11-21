# RFC 8693 token exchange in the runtime

Status: **proposal**, 2026-11-10. No code yet. The owner's decisions of
2026-11-13 (HAI-977) are recorded in
[§11](#11-decisions-owner-2026-11-13).
Audit with citations: [oidc-token-exchange-audit.md](oidc-token-exchange-audit.md)
(finding IDs `A1`–`A15` below refer to it).
See also: [oidc-token-exchange-ietf-review.md](oidc-token-exchange-ietf-review.md)
— delta list against the current IETF delegation drafts (HAI-992), 2026-11-11.

## 1. Goal

A harness session in kei-proxy acts for a human user or a service principal.
When the agent calls a downstream API, that API needs a token that says three
things:

1. who the subject is,
2. which runtime installation is acting for them,
3. that the token is good only for that one API.

Today the runtime can only hand out:

- third-party connector credentials (through I11), or
- a broad, raw `subject` JWT, for service principals only (`session:subjectToken`).

This spec adds one thing: a short-lived, audience-restricted, Kei-issued JWT
carrying an RFC 8693 `act` claim. The runtime obtains it by RFC 8693 token
exchange and releases it like any other session credential.

Non-goals:

- exchanging into third-party providers' tokens (Entra OBO and ID-JAG stay
  ADR-036 connector work);
- refresh tokens;
- impersonation tokens (never issued, Q4);
- exposing an exchange endpoint to customers or harnesses directly (Q2).

## 2. Roles

**Installation id token.** The credential a runtime installation
authenticates with (`KEI_RUNTIME_TOKEN`). Earlier drafts of this spec called
it the "runtime token"; it is the same token. It identifies exactly one
runtime installation, and that installation's id is the actor of every
exchanged token (Q3).

| RFC 8693 role | Kei component | Why |
|---|---|---|
| Security token service (STS) / authorization server | **kei-oidc-bridge** | It is the only Kei issuer. It already holds the ES256 keys and the JWKS (ADR-032: "the identity service mints every Kei user token"). It already runs the closest thing to an exchange (I11). Signing keys must never sit in a tenant runtime, and the catalog has no signer. |
| Client | **kei-proxy** (one runtime installation) | It holds the session, makes the local decision, and authenticates with its installation id token. |
| Subject | The session's user (`user:<uuid>`) or service principal (`service_principal:<uuid>`) | Resolved by one synchronous platform call at session start (Q6), never taken from the caller. |
| Actor | The runtime installation, identified by its installation id token; `act.sub` is the installation id | The runtime cannot choose it, and it presents no separate `actor_token` (Q3). |
| Policy | Catalog, two ways: the local PDP decides from the bundle, and the STS re-checks the audience against the connectors registered in the caller's workspace | "Kei decides." |
| Resource server | A Kei-trusting API: the analytics server, Kei's own services, or a customer API that federates with `https://app.haikeilabs.com` | It validates by I8 plus the profile in §5. |

Kei still never holds customer secrets. The exchanged token is minted by Kei
from Kei identity alone, and no provider credential is involved.

## 3. Flows

### 3.1 User session → delegated token (primary)

```text
harness ──PUT /v1/session {source, external_id}──▶ kei-proxy
kei-proxy: one synchronous platform call: harness identity → Kei subject + session-scoped subject token
          (platform unreachable ─▶ session not opened, fail closed)
harness ──POST /v1/credentials:release {tool, connector{connector_id, capability}, resource}──▶ kei-proxy
kei-proxy: local PDP allow?                       ── deny ─▶ reason_code, no token
kei-proxy: cached token for (session, audience, scope) with >60 s left? ── yes ─▶ return it
kei-proxy ──POST /api/v1/tokens:exchange (RFC 8693 form)──▶ gateway ─▶ kei-oidc-bridge
          Authorization: Bearer <installation id token>   (client auth, via runtime:authenticate)
          subject_token=<session subject JWT>, subject_token_type=urn:ietf:params:oauth:token-type:jwt
          audience=<descriptor audience>, scope=<descriptor scope>,
          requested_token_type=urn:ietf:params:oauth:token-type:access_token
bridge: verify, check the audience belongs to a connector in the workspace, mint at+jwt with act{sub: <installation id>}
kei-proxy ──credential {value, expires_at, resource=audience}──▶ harness ──▶ downstream API
```

The harness calls the downstream API directly, as in ADR-039.

### 3.2 Service-principal session → delegated token

This is the same flow. The subject is `service_principal:<uuid>` and the
actor is still the installation. It replaces `POST /v1/session:subjectToken`,
which is retired (Q7), for workloads such as the analytics seed job. Those
workloads receive an audience-restricted token (`aud: kei-analytics`) instead
of the raw `kei-gateway` subject token (A3).

### 3.3 Delegation, not impersonation

Every exchanged token carries `act`, so it is always **delegation** in the
RFC 8693 §1.1 sense. This holds even for a service principal, because the
installation is still a separate actor. Kei **never issues impersonation
tokens** (no `act`, where the actor is indistinguishable from the user); this
is decided (Q4), not deferred. An API that needs "the user themselves" should
use the user's own OIDC login, which is the owner's analytics SSO decision of
2026-11-01.

## 4. STS method (kei-oidc-bridge)

`POST /api/v1/tokens:exchange`

- **Path:** an AIP custom method on the `tokens` collection (ADR-019). RFC
  8693 does not fix a path; it only says the request goes to "the token
  endpoint". The method has a single client and is not a public OAuth token
  endpoint, so it follows Kei conventions. The exchange is runtime-only: the
  public `/token` endpoint does not accept the token-exchange grant, and
  discovery does not advertise it (Q2).
- **Listener:** the gateway listener only, the same way I11 is served
  (`gateway` auth mode). The gateway's extAuth calls `runtime:authenticate`
  with the installation id token and the subject token, then stamps the
  installation, workspace and subject. In `catalog` mode the bridge makes that
  call itself.
- **Wire format:** RFC 8693 exactly, so a standard client library can call it.

**Request** (`application/x-www-form-urlencoded`, RFC 8693 §2.1):

| Parameter | Kei rule |
|---|---|
| `grant_type` | REQUIRED, `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | REQUIRED. A session-scoped Kei `subject` JWT (`typ=subject`, `aud ∋ kei-gateway`) whose workspace equals the installation id token's workspace |
| `subject_token_type` | REQUIRED, `urn:ietf:params:oauth:token-type:jwt` |
| `actor_token`, `actor_token_type` | MUST be absent. The actor is the installation that authenticated with the installation id token (Q3). Present: `invalid_request`. |
| `audience` | REQUIRED, exactly one. It must belong to a connector registered in the caller's workspace (§6, Q1) |
| `resource` | OPTIONAL. If present, it must equal the resource URI on that connector's descriptor |
| `scope` | OPTIONAL. It must be a subset of the scopes on that connector's descriptor; empty means the descriptor's default |
| `requested_token_type` | OPTIONAL. Only `urn:ietf:params:oauth:token-type:access_token` is accepted; anything else gets `invalid_request` |

**Success response** (200, `application/json`, `Cache-Control: no-store`,
RFC 8693 §2.2.1):

```json
{
  "access_token": "<jwt>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "analytics:read"
}
```

No `refresh_token` is ever returned.

**Errors** use RFC 6749 §5.2 and RFC 8693 §2.2.2, with `error`,
`error_description` and a Kei `reason`:

| HTTP | `error` | `reason` | When |
|---|---|---|---|
| 401 | `invalid_client` | `installation_id_token_invalid` | The installation id token is missing, revoked or rotated away |
| 400 | `invalid_request` | `subject_token_invalid` | The subject token is bad: signature, `typ`, `exp`, `iss` or `aud`. A workspace mismatch also lands here, as do actor parameters present or a missing required parameter |
| 400 | `invalid_target` | `audience_not_registered` | The audience does not belong to any connector registered in the caller's workspace |
| 400 | `invalid_scope` | `scope_not_allowed` | The scope exceeds the connector descriptor's scopes |
| 400 | `unauthorized_client` | `exchange_disabled` | Exchange is turned off for this org or installation |
| 400 | `unsupported_grant_type` | — | Wrong `grant_type` |
| 503 | `temporarily_unavailable` | `catalog_unavailable` | The catalog check could not run. Fail closed. |

## 5. Issued token profile (RFC 9068 + RFC 8693)

**JOSE header:** `{"alg":"ES256","kid":"<active>","typ":"at+jwt"}`.

| Claim | Value |
|---|---|
| `iss` | `https://app.haikeilabs.com` |
| `sub` | the subject token's `sub`: `<user uuid>` or `service_principal:<uuid>` |
| `aud` | the single requested audience |
| `typ` (payload) | `exchanged`, a **new** I8 kind. Existing verifiers that allow-list `access` or `subject` reject it, and verifiers for it reject the old kinds. |
| `act` | `{"sub":"<installation id>"}`, always present (Q3, Q4) |
| `client_id` | the runtime installation ID (RFC 9068 §2.2, RFC 8693 §4.3) |
| `workspace_id`, `org_id` | from the installation id token |
| `scope` | the granted scopes (space-delimited) |
| `iat`, `nbf`, `exp` | `exp = min(iat + 300 s, subject exp)`, configurable up to 900 s (Q5) |
| `jti` | random, and logged at issue |

How a resource server validates the token:

- Apply I8: pin ES256, look up the `kid` in `/jwks`, and refetch once on an
  unknown kid.
- Check `iss`, `exp`, `nbf` and `typ=exchanged`.
- Require **its own** audience.
- Make authorization decisions on top-level claims and the current `act` only
  (RFC 8693 §4.1).

Nested `act` (a chain such as agent → subagent) is not produced in phase 1–3.
Subagent hops keep using `invoking_subject` and span IDs in audit.

## 6. Policy checks before exchange (fail closed at each step)

1. **Runtime (local PDP), at `POST /v1/credentials:release`:**
   - The session is live and linked, and the tool is registered.
   - The policy is allowed for the exact tuple of tool, connector, capability
     and resource.
   - The connector's v2 descriptor has `credential_source: kei_token_exchange`.
     The `audience` and `scope` come **from the verified bundle descriptor,
     never from the caller**.

   This is the existing credential-release path with one new credential
   source.
2. **STS:**
   - The installation id token is valid. The subject token is valid, and its
     workspace matches the installation id token's.
   - If the subject token carries `may_act` (phase 3), its `sub` equals this
     installation's id.
   - The audience belongs to a connector registered in the caller's
     workspace, and the scope is a subset of that connector descriptor's
     scopes.

   The audience is an attribute of the existing connector, carried on its
   descriptor; there is no separate exchange-audience resource (Q1). This is a
   contract between bridge identities and catalog connectors: the bridge reads
   the workspace's registered connectors from the catalog to resolve
   audiences. The catalog connector is the source of truth, and the bridge
   keeps no second copy.
3. **Kill switches** (any one of these denies):
   - an org flag at the STS;
   - the `POLICY_BUNDLE_V2_CONNECTORS` gate, which already controls
     descriptors;
   - removing the connector from the workspace, or removing the audience from
     its descriptor;
   - revoking the installation id token.

The STS never re-decides tool policy. That stays local (ADR-011). It only
refuses to mint for an audience outside the connectors registered in the
caller's workspace.

## 7. Runtime surface

There is **no new socket route** for user sessions. Exchanged tokens are
released by the existing `POST /v1/credentials:release`
(`kei.credential-release-request/v1`):

- **Request:** unchanged.
- **Response:** unchanged. It returns `credential.value` (the JWT),
  `credential.expires_at` and `credential.resource` (the audience).
- **New deny `reason_code`s**, each with no credential and no fallback:
  `token_exchange_denied` (an STS 4xx, with the STS `reason` passed through),
  `token_exchange_unavailable` (an STS 5xx or a timeout) and
  `descriptor_invalid` (the audience is missing from the descriptor).
- **New descriptor field** in the kei-connector-contracts
  `policy-set-v2.schema.json`: `credential_source: "kei_token_exchange"`, with
  `exchange: {audience, resource?, scopes[]}`. This is where the connector's
  audience lives (Q1). It needs a contracts release, and the runtime and
  catalog pins must move together (both pin that schema byte-for-byte).

`POST /v1/session:subjectToken` is **retired** (Q7); token exchange replaces
it. Its callers move to `credentials:release` with a `kei_token_exchange`
connector, the analytics sidecar accepts `typ=exchanged` with
`aud=kei-analytics` instead of `typ=subject`, and the route is then removed
(phase 3).

There is **no CLI surface**. `kei-proxy authorize` is the deprecated one-shot
path and returns `preflight_required`. The `kei` admin CLI is admin-only. An
audience is set on the connector's descriptor through the existing connector
surfaces (the catalog API and `kei connectors`); there is no
`exchange-audiences` resource or command (Q1).

## 8. Caching and expiry

- **Cache key:** `(session_id, audience, scope)`. Entries live in the
  session's in-memory credential store, are never written to disk and are
  never logged.
- **Reuse:** a cached token is reused while it has more than 60 s left;
  otherwise the runtime exchanges again.
- **Flush:** the store is zeroed when the session ends or when the
  idle TTL or maximum age is reached (`docs/sessions.md`).
- **Bundle changes:** the store is also flushed on bundle reconciliation when
  the descriptor or the connector's registration changes, and on revocation
  of the installation id token.
- **Refresh:** there is none. Exchange again.
- **Lifetime:** 300 s by default, 900 s at most, and never past the subject
  token's `exp`.
- **Revocation:** expiry only (A9, Q5). A short lifetime plus audience
  restriction is the control. Kei keeps no `jti` deny-list and offers no
  introspection. Revocation is future platform work, delivered through the
  approvals page and its endpoints, admin-only
  (HAI-983).

## 9. Audit

| Where | Fields (never the token) |
|---|---|
| Runtime decision event, on the existing `credentials:release` record | `invoking_subject`, `agent_id`, `session_id`, `tool`, `connector_id`, `capability`, `resource` (= audience), `decision`, `reason_code`, and in `policy_reason`: `token_exchange jti=<jti> exp=<RFC3339> scope=<scope>`. The catalog's `audit:flush` rejects unknown fields, so these values ride in `policy_reason`, as `session:subjectToken` does today. |
| STS issuance log (structured) and metric | `request_id`, `jti`, `sub`, `act.sub` (installation id), `client_id` (installation), `workspace_id`, `aud`, `scope`, `exp`, `outcome`, `reason` |

The `jti` joins the runtime record, the STS log and any resource-server log.

## 10. Failure modes

Every failure is a deny for that call, with no fallback to I11, to the raw
subject token, or to a broader audience:

- the STS cannot be reached, times out, or returns a 5xx (`token_exchange_unavailable`);
- the STS returns a 4xx (`token_exchange_denied`);
- the response is malformed, or its `issued_token_type` or `aud` does not
  match the request: the runtime checks both before releasing;
- the session's subject token expires within 60 s: the call is denied, and a
  new session is needed;
- the bundle is stale or revoked, or the descriptor is invalid.

The runtime retries an STS transport error once within the call. A 4xx is
never retried.

**Platform liveness (Q6).** Subject resolution is one synchronous call to the
platform at session start, so liveness between runtime and platform matters
more than when subject tokens rode in the bundle:

- while the platform is unreachable, a **new session fails closed**: it is not
  opened, and no token pull or permission check runs for it;
- an **existing session keeps working** until its subject token expires, then
  its calls are denied until a new session can be opened.

## 11. Decisions (owner, 2026-11-13)

The owner decided the seven questions this section used to ask
(HAI-977).

**Q1. Audience registry.** An exchange audience is an attribute of the
existing connector (its descriptor), not a new `exchange-audiences` catalog
resource. kei-oidc-bridge performs the exchange and issues a token only for an
audience that belongs to a connector registered in the caller's workspace.
That is a contract between bridge identities and catalog connectors: the
bridge reads the workspace's registered connectors to resolve audiences. The
catalog connector is the source of truth; the bridge keeps no second copy.

**Q2. Public endpoint.** The exchange is runtime-only. The public `/token`
endpoint does not accept it.

**Q3. Actor token.** The actor is the installation id token. "Runtime token"
and "installation id token" are the same token, and this spec uses
"installation id token" (defined in §2). `act.sub` is the installation id.
The runtime presents no separate `actor_token`.

**Q4. Impersonation.** Kei never issues impersonation tokens. Every exchanged
token carries `act`.

**Q5. Revocation.** Expiry only: 300 s by default, 900 s at most. Revocation
is future platform work, delivered through the approvals page and its
endpoints, admin-only (tracked in
HAI-983). There is no `jti`
deny-list.

**Q6. Bundle token fan-out (A1/A2).** Today the harness identity (a
system-local Entra ID or Google SSO id) is looked up to a Kei user id. That
lookup moves to one synchronous call at session start, before any token pull
or permission check. Subject tokens become session-scoped and leave the
policy bundle. As a consequence, liveness between runtime and platform
matters more: a new session fails closed while the platform is unreachable,
and an existing session keeps working until its token expires (§10).

**Q7. Retire `session:subjectToken`.** `POST /v1/session:subjectToken` is
retired; token exchange replaces it (§7).

## 12. Phased rollout and test plan

| Phase | Scope | Repos | Done when |
|---|---|---|---|
| 0. Prerequisites | Add `token_endpoint`, `authorization_endpoint` and `userinfo_endpoint` to discovery (A8); discovery does not advertise the exchange grant (Q2). Record an I8 `contract_change` for `typ=exchanged`, `at+jwt`, `act` and `client_id`. Force `observe` modes off for the runtime client. | bridge | Discovery passes an OIDC Discovery check; the I8 contract change is captured |
| 1. STS behind a flag | Add `POST /api/v1/tokens:exchange` on the gateway listener, gated by `TOKEN_EXCHANGE_ENABLED` (default off), service principals only. The bridge resolves audiences from the workspace's registered connectors (Q1). | bridge, catalog, gateway route | Unit and contract tests below are green; a staging exchange for `analytics-seed` → `kei-analytics` succeeds |
| 2. Runtime release | Add the descriptor `credential_source: kei_token_exchange` (contracts release, then catalog and runtime pins). Make `credentials:release` exchange, cache and audit. Enable it for user sessions. | contracts, catalog, runtime | Runtime tests and the playground e2e below are green |
| 3. Hardening | Add `may_act` for the installation id to subject tokens. Bundle fan-out is decided (Q6): subject tokens are session-scoped, resolved by one synchronous call at session start, and leave the policy bundle. Move analytics to `typ=exchanged` and retire `session:subjectToken` (Q7). | bridge, catalog, runtime, analytics | The export route's traffic is zero; bundles carry no subject tokens; a cross-installation replay is rejected |

Tests, by phase:

- **Bridge (phase 1).** Table tests over every row of the §4 error table:
  - wrong `grant_type`, missing `subject_token_type`, `actor_token` present;
  - `typ=cli`, `typ=access` or `typ=id` presented as the subject;
  - an expired subject token, or one 1 s from expiry (`exp` clamped);
  - a cross-workspace installation id token; an audience that belongs to no
    connector registered in the workspace; a scope superset; the flag off;
  - a catalog outage (503, with no token minted).

  A golden claims test checks the header `typ=at+jwt`, the payload
  `typ=exchanged`, `act.sub` equal to the installation id, `client_id`, a
  single `aud`, and `exp ≤ subject exp`. Further tests:

  - Existing `Verify(..., TypeAccess)` and `Verify(..., TypeSubject)` callers
    reject an exchanged token.
  - The JWKS rotation test still verifies after a kid rotation.
  - A log test confirms no token value appears in any log line.
- **Runtime (phase 2).**
  - `credentials:release` table tests: a deny never calls the STS; an allow
    calls it once; a cache hit makes no call; a token with ≤60 s left
    re-exchanges.
  - The audience and scope come from the descriptor even when the caller sends
    others.
  - An STS 4xx gives `token_exchange_denied` with no retry; an STS 5xx or
    timeout gives one retry and then `token_exchange_unavailable`.
  - A response with an `aud` or `issued_token_type` mismatch is rejected.
  - Ending the session or reconciling the bundle flushes the cache.
  - Audit records carry `jti` and never the token, and a `go test -race` run
    passes.
- **Contracts.**
  - Schema fixtures for a valid `kei_token_exchange` descriptor, and for
    invalid ones: a missing audience, or unknown fields.
  - The catalog and runtime schema copies are byte-identical.
- **End to end (playground).**
  - A user session gets a token from the analytics server, which accepts it.
  - The same token is rejected by `runtime:authenticate` and I11 (wrong
    `typ`/`aud`).
  - A principal session works the same way.
  - Removing the connector from the workspace makes the next exchange deny.
  - Phase 3: a subject token with `may_act` for installation A, presented by
    installation B, is rejected.
  - Phase 3: with the platform unreachable, opening a new session fails
    closed, and an existing session keeps working until its subject token
    expires.
