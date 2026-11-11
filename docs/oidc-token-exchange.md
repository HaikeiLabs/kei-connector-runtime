# RFC 8693 token exchange in the runtime

Status: **proposal**, 2026-11-10. No code yet. Open questions for the owner
are in [§11](#11-open-questions-for-the-owner).
Audit with citations: [oidc-token-exchange-audit.md](oidc-token-exchange-audit.md)
(finding IDs `A1`–`A15` below refer to it).
See also: [oidc-token-exchange-ietf-review.md](oidc-token-exchange-ietf-review.md)
— delta list against the current IETF delegation drafts (HAI-992), 2026-11-11.

## 1. Goal

A harness session in kei-proxy acts for a human user or a service principal.
When the agent calls a downstream API, that API needs a token that says three
things:

1. who the subject is,
2. which agent is acting for them,
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
- impersonation tokens;
- exposing an exchange endpoint to customers or harnesses directly.

## 2. Roles

| RFC 8693 role | Kei component | Why |
|---|---|---|
| Security token service (STS) / authorization server | **kei-oidc-bridge** | It is the only Kei issuer. It already holds the ES256 keys and the JWKS (ADR-032: "the identity service mints every Kei user token"). It already runs the closest thing to an exchange (I11). Signing keys must never sit in a tenant runtime, and the catalog has no signer. |
| Client | **kei-proxy** (one runtime installation) | It holds the session, makes the local decision, and authenticates with its runtime token. |
| Subject | The session's user (`user:<uuid>`) or service principal (`service_principal:<uuid>`) | Taken from the verified bundle, never from the caller. |
| Actor | The installation's agent (`agent:<uuid>`), resolved from the runtime token | The runtime cannot choose it. |
| Policy | Catalog, two ways: the local PDP decides from the bundle, and the STS re-checks the audience against catalog state | "Kei decides." |
| Resource server | A Kei-trusting API: the analytics server, Kei's own services, or a customer API that federates with `https://app.haikeilabs.com` | It validates by I8 plus the profile in §5. |

Kei still never holds customer secrets. The exchanged token is minted by Kei
from Kei identity alone, and no provider credential is involved.

## 3. Flows

### 3.1 User session → delegated token (primary)

```text
harness ──PUT /v1/session {source, external_id}──▶ kei-proxy   (subject from bundle)
harness ──POST /v1/credentials:release {tool, connector{connector_id, capability}, resource}──▶ kei-proxy
kei-proxy: local PDP allow?                       ── deny ─▶ reason_code, no token
kei-proxy: cached token for (session, audience, scope) with >60 s left? ── yes ─▶ return it
kei-proxy ──POST /api/v1/tokens:exchange (RFC 8693 form)──▶ gateway ─▶ kei-oidc-bridge
          Authorization: Bearer <runtime token>      (client auth, via runtime:authenticate)
          subject_token=<session subject JWT>, subject_token_type=urn:ietf:params:oauth:token-type:jwt
          audience=<descriptor audience>, scope=<descriptor scope>,
          requested_token_type=urn:ietf:params:oauth:token-type:access_token
bridge: verify, check binding, mint at+jwt with act{sub: agent:<id>}
kei-proxy ──credential {value, expires_at, resource=audience}──▶ harness ──▶ downstream API
```

The harness calls the downstream API directly, as in ADR-039.

### 3.2 Service-principal session → delegated token

This is the same flow. The subject is `service_principal:<uuid>` and the
actor is still the agent. It replaces `POST /v1/session:subjectToken` for
workloads such as the analytics seed job. Those workloads receive an
audience-restricted token (`aud: kei-analytics`) instead of the raw
`kei-gateway` subject token (A3).

### 3.3 Delegation, not impersonation

Every exchanged token carries `act`, so it is always **delegation** in the
RFC 8693 §1.1 sense. This holds even for a service principal, because the
agent is still a separate actor. Impersonation (no `act`, where the agent is
indistinguishable from the user) is **not offered**. An API that needs "the
user themselves" should use the user's own OIDC login, which is the owner's
analytics SSO decision of 2026-11-01. Adding impersonation later is open
question Q4.

## 4. STS method (kei-oidc-bridge)

`POST /api/v1/tokens:exchange`

- **Path:** an AIP custom method on the `tokens` collection (ADR-019). RFC
  8693 does not fix a path; it only says the request goes to "the token
  endpoint". The method has a single client and is not a public OAuth token
  endpoint, so it follows Kei conventions. Whether also to accept the grant at
  `/token` for third-party clients is Q2.
- **Listener:** the gateway listener only, the same way I11 is served
  (`gateway` auth mode). The gateway's extAuth calls `runtime:authenticate`
  with the runtime token and the subject token, then stamps the installation,
  workspace and subject. In `catalog` mode the bridge makes that call itself.
- **Wire format:** RFC 8693 exactly, so a standard client library can call it.

**Request** (`application/x-www-form-urlencoded`, RFC 8693 §2.1):

| Parameter | Kei rule |
|---|---|
| `grant_type` | REQUIRED, `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | REQUIRED. A Kei `subject` JWT (`typ=subject`, `aud ∋ kei-gateway`) whose workspace equals the runtime token's workspace |
| `subject_token_type` | REQUIRED, `urn:ietf:params:oauth:token-type:jwt` |
| `actor_token`, `actor_token_type` | MUST be absent in phase 1–2. The actor is the authenticated client's agent (Q3). Present: `invalid_request`. |
| `audience` | REQUIRED, exactly one. It must be a registered Kei resource (§6) |
| `resource` | OPTIONAL. If present, it must equal the registered resource URI for `audience` |
| `scope` | OPTIONAL. It must be a subset of the registered scopes for the audience; empty means the registered default |
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
| 401 | `invalid_client` | `runtime_token_invalid` | The runtime token is missing, revoked or rotated away |
| 400 | `invalid_request` | `subject_token_invalid` | The subject token is bad: signature, `typ`, `exp`, `iss` or `aud`. A workspace mismatch also lands here, as do actor parameters present or a missing required parameter |
| 400 | `invalid_target` | `audience_not_registered` / `audience_not_bound` | The audience is unknown, or it is not bound to this installation's agent in this workspace |
| 400 | `invalid_scope` | `scope_not_allowed` | The scope exceeds what is registered |
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
| `act` | `{"sub":"agent:<agent uuid>","kei_installation_id":"<uuid>"}` |
| `client_id` | the runtime installation ID (RFC 9068 §2.2, RFC 8693 §4.3) |
| `workspace_id`, `org_id` | from the runtime token |
| `scope` | the granted scopes (space-delimited) |
| `iat`, `nbf`, `exp` | `exp = min(iat + 300 s, subject exp)`, configurable up to 900 s |
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
   - The runtime token is valid. The subject token is valid, and its
     workspace matches the runtime token's.
   - If the subject token carries `may_act` (phase 3), its `sub` equals this
     installation's agent.
   - The audience is a registered resource bound to this agent in this
     workspace, and the scope is a subset of what is registered.

   The registry is a catalog resource, `exchange-audiences` (AIP), which a
   connector of kind `kei_resource` references (Q1). The STS reads it through
   `runtime:authenticate`'s response, or through a cached catalog lookup, the
   same way it reads bindings for I11.
3. **Kill switches** (any one of these denies):
   - an org flag at the STS;
   - the `POLICY_BUNDLE_V2_CONNECTORS` gate, which already controls
     descriptors;
   - unbinding the agent or the audience;
   - revoking the runtime token.

The STS never re-decides tool policy. That stays local (ADR-011). It only
refuses to mint outside what the catalog says this installation may reach.

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
  `exchange: {audience, resource?, scopes[]}`. This needs a contracts release,
  and the runtime and catalog pins must move together (both pin that schema
  byte-for-byte).

`POST /v1/session:subjectToken` stays as it is until phase 3. Its callers
move to `credentials:release` with a `kei_token_exchange` connector, and the
route is then deprecated.

There is **no CLI surface**. `kei-proxy authorize` is the deprecated one-shot
path and returns `preflight_required`. The `kei` admin CLI is
admin-only. Registering an audience goes through the catalog API, plus a
`kei exchange-audiences` command in kei-cli per ADR-019 step 4 (phase 2).

## 8. Caching and expiry

- **Cache key:** `(session_id, audience, scope)`. Entries live in the
  session's in-memory credential store, are never written to disk and are
  never logged.
- **Reuse:** a cached token is reused while it has more than 60 s left;
  otherwise the runtime exchanges again.
- **Flush:** the store is zeroed when the session ends or when the
  idle TTL or maximum age is reached (`docs/sessions.md`).
- **Bundle changes:** the store is also flushed on bundle reconciliation when
  the subject's identity, the descriptor or the binding changes, and on
  runtime-token revocation.
- **Refresh:** there is none. Exchange again.
- **Lifetime:** 300 s by default, 900 s at most, and never past the subject
  token's `exp`.
- **Revocation:** none beyond expiry (A9). A short lifetime plus audience
  restriction is the mitigation. Q5 asks for a `jti` deny-list.

## 9. Audit

| Where | Fields (never the token) |
|---|---|
| Runtime decision event, on the existing `credentials:release` record | `invoking_subject`, `agent_id`, `session_id`, `tool`, `connector_id`, `capability`, `resource` (= audience), `decision`, `reason_code`, and in `policy_reason`: `token_exchange jti=<jti> exp=<RFC3339> scope=<scope>`. The catalog's `audit:flush` rejects unknown fields, so these values ride in `policy_reason`, as `session:subjectToken` already does. |
| STS issuance log (structured) and metric | `request_id`, `jti`, `sub`, `act.sub`, `client_id` (installation), `workspace_id`, `aud`, `scope`, `exp`, `outcome`, `reason` |

The `jti` joins the runtime record, the STS log and any resource-server log.

## 10. Failure modes

Every failure is a deny for that call, with no fallback to I11, to the raw
subject token, or to a broader audience:

- the STS cannot be reached, times out, or returns a 5xx (`token_exchange_unavailable`);
- the STS returns a 4xx (`token_exchange_denied`);
- the response is malformed, or its `issued_token_type` or `aud` does not
  match the request: the runtime checks both before releasing;
- the subject token in the bundle expires within 60 s: wait for the bundle
  refresh;
- the bundle is stale or revoked, or the descriptor is invalid.

The runtime retries an STS transport error once within the call. A 4xx is
never retried.

## 11. Open questions for the owner

1. **Q1. Audience registry.** Should exchange audiences be a new catalog
   resource (`exchange-audiences`), or a connector kind (`kei_resource`) whose
   descriptor carries the audience? The connector kind reuses
   bindings, policy and descriptors with the least new surface, and it is this
   spec's lean.
2. **Q2. Public endpoint.** Should the STS accept the exchange grant at
   `/token` and advertise it in discovery, for non-Kei clients? This spec
   keeps the method runtime-only.
3. **Q3. Actor token.** Should the actor stay derived from the
   runtime token? Or should the runtime present an `actor_token`, which would
   need an agent-identity JWT that does not exist today? The derived actor is
   simpler and cannot be forged by the runtime.
4. **Q4. Impersonation.** Should Kei ever issue tokens without
   `act`? This spec says no.
5. **Q5. Revocation.** Is expiry enough for 5-minute tokens, or does Kei
   need a `jti` deny-list or introspection (A9)?
6. **Q6. Bundle token fan-out (A1/A2).** Should bundles stop carrying subject
   tokens for every workspace identity? The alternative is short-lived
   (≤15 min) subject tokens that carry `may_act` for the installation's agent,
   minted per session on demand through I12. This is the most valuable
   hardening, and it is cross-repo (catalog, bridge and runtime). Phase 3
   assumes `may_act` is added. Moving to on-demand minting is the owner's
   call.
7. **Q7. Retire `session:subjectToken`.** Should the analytics sidecar move
   from accepting `typ=subject` to accepting `typ=exchanged` with
   `aud=kei-analytics`, so the export route can be retired?

## 12. Phased rollout and test plan

| Phase | Scope | Repos | Done when |
|---|---|---|---|
| 0. Prerequisites | Add `token_endpoint`, `authorization_endpoint` and `userinfo_endpoint` to discovery (A8). Record an I8 `contract_change` for `typ=exchanged`, `at+jwt`, `act` and `client_id`. Force `observe` modes off for the runtime client. | bridge | Discovery passes an OIDC Discovery check; the I8 contract change is captured |
| 1. STS behind a flag | Add `POST /api/v1/tokens:exchange` on the gateway listener, gated by `TOKEN_EXCHANGE_ENABLED` (default off), service principals only. Add the audience registry (Q1). | bridge, catalog, gateway route | Unit and contract tests below are green; a staging exchange for `analytics-seed` → `kei-analytics` succeeds |
| 2. Runtime release | Add the descriptor `credential_source: kei_token_exchange` (contracts release, then catalog and runtime pins). Make `credentials:release` exchange, cache and audit. Enable it for user sessions. | contracts, catalog, runtime, kei-cli | Runtime tests and the playground e2e below are green |
| 3. Hardening | Add `may_act` to subject tokens (Q6). Move analytics to `typ=exchanged` and deprecate `session:subjectToken` (Q7). Decide on bundle fan-out (Q6). | bridge, catalog, runtime, analytics | The export route's traffic is zero; a cross-installation replay is rejected |

Tests, by phase:

- **Bridge (phase 1).** Table tests over every row of the §4 error table:
  - wrong `grant_type`, missing `subject_token_type`, `actor_token` present;
  - `typ=cli`, `typ=access` or `typ=id` presented as the subject;
  - an expired subject token, or one 1 s from expiry (`exp` clamped);
  - a cross-workspace runtime token; an unknown or unbound audience; a scope
    superset; the flag off;
  - a catalog outage (503, with no token minted).

  A golden claims test checks the header `typ=at+jwt`, the payload
  `typ=exchanged`, `act.sub`, `client_id`, a single `aud`, and `exp ≤ subject
  exp`. Further tests:

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
  - Unbinding the audience makes the next release deny within one bundle
    refresh.
  - Phase 3: a subject token with `may_act` for agent A, presented by agent
    B's installation, is rejected.
