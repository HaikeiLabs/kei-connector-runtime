# OIDC and RFC 8693 token exchange: as-built audit

Status: audit, 2026-11-10. Read-only. No code changed.
Companion spec: [oidc-token-exchange.md](oidc-token-exchange.md).

This page records how identity tokens work across Kei today, with file and
line citations, and lists the gaps against OpenID Connect Core 1.0, OpenID
Connect Discovery / RFC 8414, RFC 9068 (JWT access tokens), RFC 7519/7515 and
RFC 8693 (token exchange). No token, key or secret value was read or printed.

Repos and commits read:

| Repo | Commit | Cited as |
|---|---|---|
| kei-connector-runtime (this repo) | `b7666c6` | `path:line` |
| kei-oidc-bridge | `ab3f4c0` | `bridge:path:line` |
| kei-policy-catalog | `6248f2d` | `catalog:path:line` |
| kei (ADRs) | `ebaa2e2a` | `kei:path:line` |

## Summary

- Kei has one issuer, kei-oidc-bridge at `https://app.haikeilabs.com`. It
  signs every Kei JWT with ES256 and publishes `/jwks` (ADR-032,
  `kei:docs/adr/032-identity-service-ownership.md:125-134`). The catalog only
  mints the opaque runtime token.
- The bridge `/token` endpoint supports only `authorization_code`. It has no
  refresh, client-credentials or token-exchange grant
  (`bridge:internal/oidcprovider/oidc.go:263-265`).
- Kei already runs a **proprietary token exchange**. The runtime sends its
  runtime token (client authentication) and a user's or service principal's
  `subject` JWT (`X-Kei-Subject-Token`) to I11
  `POST /api/v1/connectorCredentials[/{id}]:resolve` and gets a connector
  credential back (`internal/credrelease/client.go:115-130`,
  `internal/credrelease/connector.go:22-23,56-70`). It is not RFC 8693: no
  `grant_type`, no token type URIs, no `act`, no audience or scope request,
  and it returns third-party provider tokens, not Kei-issued tokens.
- The `subject` JWT is the Kei identity that a runtime session acts for. The
  catalog pre-mints one for **every linked identity in the workspace**, with
  a lifetime of up to 8 h, and ships them inside every policy bundle to every
  installation in that workspace. The runtime persists that bundle to disk.
  This is the largest risk found (finding A1).
- Nothing in any of the four repos implements `act`, `may_act`,
  `actor_token`, `subject_token_type`, `issued_token_type`, `jti` replay
  tracking, token revocation or introspection. RFC 8693 appears only in
  ADR-036's ID-JAG design text (`kei:docs/adr/036-generic-connectors.md:421-423`).

## 1. kei-oidc-bridge (the issuer)

### Endpoints

- **OIDC endpoints.** The route table is at `bridge:internal/server/router.go:56-149`.
  - `/.well-known/openid-configuration` (:69), `/authorize` (:70), `/token` (:71), `/userinfo` (:72) and `/jwks` (:73).
  - The public HTTPRoute exposes only `/jwks` and discovery
    (`bridge:deploy/helm/oidc-bridge/templates/httproute.yaml:69-73`).
    `/authorize`, `/token` and `/userinfo` "are not routed publicly"
    (`bridge:internal/oidcprovider/oidc.go:143-145`).
- **Service-key mints.** These use `X-KEI-API-Key` with a constant-time compare
  (`bridge:internal/apiv1/apiv1.go:119-126`).
  - `POST /api/v1/sessions`, `/api/v1/cliTokens` and `/api/v1/subjectTokens:batchCreate` (`bridge:internal/server/router.go:116-118`).
  - Device-authorization approve, deny and lookup (:130-132).
- **Device flow (RFC 8628 style).** Create and `:exchange` are public AIP
  methods (`bridge:internal/server/router.go:128-129`), not a `/token` grant.
- **Credential release (I11).**
  - `POST /api/v1/connectorCredentials:resolve` and `/api/v1/connectorCredentials/{connector}:resolve`
    (`bridge:internal/server/credential_release.go:14,42-44`).
  - Production serves I11 in `gateway` mode on the gateway listener only
    (`bridge:deploy/helm/oidc-bridge/values-prod.yaml:181-187`). The gateway's
    extAuth calls the catalog's `runtime:authenticate` and stamps `X-Kei-*`
    headers. The bridge re-verifies the subject JWT and requires it to agree
    with the stamps (`bridge:internal/connectors/resolve_auth.go:124-140`).
    In the `catalog` mode, the bridge makes that call itself (:76-122).
- **Not present:** token revocation (RFC 7009), introspection (RFC 7662), and
  `/.well-known/oauth-authorization-server` (RFC 8414).

### Discovery document (`bridge:internal/oidcprovider/oidc.go:146-157`)

| Field | Value |
|---|---|
| `issuer` | `https://app.haikeilabs.com` (`bridge:deploy/helm/oidc-bridge/values.yaml:24`) |
| `jwks_uri` | issuer + `/jwks` |
| `grant_types_supported` | `["authorization_code"]` |
| `response_types_supported` | `["code"]` |
| `id_token_signing_alg_values_supported` | `["ES256"]` |
| `token_endpoint_auth_methods_supported` | `client_secret_basic`, `client_secret_post` |
| `code_challenge_methods_supported` | `["S256"]` |
| `scopes_supported` | `openid profile email` |
| missing | `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint` |

### Signing and keys

- **Algorithm:** ES256 on P-256 only (`bridge:internal/tokensign/signer.go:148`,
  `bridge:internal/tokensign/keyset.go:97`).
- **`kid`:** the header carries the active kid. Verifiers reject an unknown kid
  (`bridge:internal/tokensign/verifier.go:107-115`).
- **Keys:** they come from AWS Secrets Manager `kei/oidc-bridge-signing-keys`
  through an ExternalSecret. Signing does not use KMS
  (`bridge:docs/token-signing.md:183-186`).
- **JWKS:** every listed key is published, with `Cache-Control: max-age=300`
  (`bridge:internal/tokensign/keyset.go:148-167`, `bridge:internal/oidcprovider/oidc.go:32,459`).
- **Rotation and retirement:** run by script (`--rotate`/`--retire`). Retirement
  waits 25 h by default (`bridge:docs/token-signing.md:223-246`). Removing a kid
  is the only way to revoke a Kei token (:248-253).
- **Legacy HS256:** the verification window closed on 2026-10-07 (:258-280).

### Token kinds

Every token carries a payload `typ` that names its kind
(`bridge:internal/tokensign/claims.go:16-22,45`). The JOSE header `typ` is
the library default `JWT` (`bridge:internal/tokensign/claims.go:12-13`). All
tokens carry `iss`, `sub`, `iat` and `exp`
(`bridge:internal/tokensign/signer.go:123-138`). None carries `nbf`, `azp`,
`auth_time`, `client_id`, `act` or `may_act`.

| `typ` | `aud` | Lifetime | Notable claims | Minted by |
|---|---|---|---|---|
| `id` | fixed `kei-client`, whatever the client (`bridge:internal/oidcprovider/oidc.go:28,464`) | 1 h | `email`, `name`, `nonce`; no `jti` | `/token` |
| `access` | **none** (`bridge:internal/tokensign/signer.go:40-45`) | 1 h | `email`, `name`; no `jti`, `scope` or `client_id` | `/token` |
| `cli` | `kei-api` | `CLI_TOKEN_TTL`, default 8 h, max 24 h (`bridge:internal/config/config.go:393-404`) | `jti`, `org_id`, `workspace_id`, `scope` | `cliTokens`, device `:exchange` |
| `session` | `kei-api` | default 24 h (`bridge:internal/config/config.go:379-384`) | `jti`, `org_id`, `workspace_id`, `scope` | `/api/v1/sessions` |
| `subject` | `kei-gateway` (`bridge:internal/tokensign/claims.go:24-28`) | 900 s by default, 28 800 s max (:30-36) | `jti`, `workspace_id`; `ext{source,external_id}` for a user; `subject_type`, `service_principal_id` for a principal (`bridge:internal/tokensign/signer.go:103-120`) | `subjectTokens:batchCreate` |

How `sub` is formed:

- A minted user token's `sub` is the Kei user UUID.
- A principal token's `sub` is `service_principal:<uuid>`
  (`bridge:internal/tokensign/signer.go:107`).
- A `/token` token's `sub` is the stored user ID
  (`bridge:internal/oidcprovider/subject.go:30-35`).

### `/token` behaviour

- **Grants:** only `authorization_code`. Anything else gets
  `unsupported_grant_type` (`bridge:internal/oidcprovider/oidc.go:263-265`).
  No refresh token is issued (:237-242,345-350). The refresh grant is
  HAI-945, which the owner approved on 2026-11-01 (wiki claim "HAI-945 filed").
- **Client authentication:** `client_secret_basic` or `client_secret_post`,
  checked against stored hashes. A per-client `token_auth: observe` mode lets
  a failed check through (`bridge:internal/oauthclient/auth.go:73-137`).
- **PKCE:** S256. It is enforced only for clients that set `require_pkce`, and
  `pkce_mode: observe` is allowed (`bridge:internal/oauthclient/pkce.go:103-138`).
- **Codes:** single-use, 10-minute lifetime, bound to `client_id` and
  `redirect_uri` (`bridge:internal/oidcprovider/oidc.go:246,291-307,379-395`).
- **Errors:** the RFC 6749 §5.2 JSON shape with `Cache-Control: no-store`
  (`bridge:internal/oidcprovider/oidc.go:411-417`). The AIP API uses
  `{error:{code,reason,message}}` (`bridge:docs/api/identity-v1.md:316-320`).

### Validation helper

`tokensign.Verifier.Verify(raw, accept ...Type)` enforces:

- a `typ` allow-list, the exact `iss`, `exp`, and 30 s of skew
  (`bridge:internal/tokensign/verifier.go:13,62-105`).
- the audience, per `typ` only: `cli`/`session` need `kei-api`, `subject`
  needs `kei-gateway`, and `access` has no audience check
  (`bridge:internal/tokensign/claims.go:115-139`).

The contract for consumers is I8 (`bridge:docs/token-signing.md:113-121`).
The analytics sidecar follows it: ES256 only, a `typ` allow-list, and
optional `aud` (wiki decision "Owner 2026-10-30: analytics OWUI sidecar
validates Kei identity tokens").

### Outbound exchanges already present (as an OAuth client, not as the server)

- **Entra on-behalf-of** (jwt-bearer, `requested_token_use=on_behalf_of`):
  `bridge:internal/sso/obo.go:21-27,59-60`. It is not wired into connect
  (:26-27).
- **ID-JAG** (an RFC 8693 exchange to `...token-type:id-jag`, then RFC 7523):
  this is an interface only, marked not implemented
  (`bridge:internal/oauth/followups.go:11-19`). It is designed in
  `kei:docs/adr/036-generic-connectors.md:421-428`. The owner deferred it on
  2026-10-18 (wiki decision "Owner questions 2026-10-18 … HAI-494 DCR/ID-JAG").

## 2. kei-policy-catalog

- **Runtime token.**
  - The opaque `kh_live_` token is 32 random bytes in hex
    (`catalog:internal/runtime/installations.go:668-674`, ADR-020). Only its
    SHA-256 is stored (`catalog:pkg/database/harness_keys.go:212`).
  - It is validated by hash lookup and scoped to org, workspace and
    installation (`catalog:internal/runtime/policy_bundle.go:311-323`,
    `catalog:pkg/database/harness_keys.go:130-137`).
  - Rotation is in place (`catalog:pkg/database/harness_keys.go:256-263`).
  - **The insert never sets `expires_at`** (`catalog:pkg/database/harness_keys.go:210-216`),
    so runtime tokens do not expire.
- **`runtime:authenticate`.**
  - Route: `catalog:internal/server/http/router.go:434`.
  - It takes the runtime bearer token plus `X-Kei-Subject-Token`
    (`catalog:internal/runtimeauth/handler.go:16,59`).
  - It verifies the JWT against the JWKS: ES256 only, `kid` required, `crit`
    rejected, and `typ`, `iss`, `aud` and `exp`/`nbf` checked with 30 s of
    leeway (`catalog:internal/runtimeauth/verifier.go:129-207`).
  - It denies `WORKSPACE_MISMATCH` when the runtime token's workspace differs
    from the JWT's workspace (`catalog:internal/runtimeauth/authenticator.go:132-135`).
  - Allows are cached for 60 s (`catalog:internal/runtimeauth/cache.go:11`).
    This is the only JWT verifier in the catalog.
- **Bundle subject tokens.** `resolveSubjectTokens`
  (`catalog:internal/runtime/policy_bundle.go:424-531`) calls the bridge's
  `subjectTokens:batchCreate` with the service key
  (`catalog:internal/identityclient/client.go:82-102`).
  - **TTL:** the time left until the bundle's `not_after` (now + 12 h), capped
    at 28 800 s. A TTL below 1 s is reset to the 28 800 s maximum
    (`catalog:internal/runtime/policy_bundle.go:436-444`).
  - **Who gets a token:** every workspace member's chat identity, each marked
    `linked` (`catalog:pkg/database/policy_bundle_builder.go:315-338`).
    Service principals get one only when bound to this installation's agent
    (`catalog:pkg/database/service_principal_bundle_subjects.go:11-42`).
- **Admin routes do not verify JWTs.** They trust an `X-User-ID` header that
  the web proxy stamps (`catalog:pkg/handlers/harness_keys.go:20-37`).
- **No RFC 8693 code**, and no token or session `:verb` route beyond those
  listed in `catalog:internal/server/http/router.go:406-434`.

## 3. kei-connector-runtime (kei-proxy)

| Area | As built |
|---|---|
| Runtime token | Comes from `KEI_RUNTIME_TOKEN` (`config.go:18,150`). The socket compares it in constant time (`serve.go:538`). It is the client credential on every control-plane and I11 call. |
| Socket routes | `runtime/socket_authorize.go:559-616`: session, authorize, `credentials:release`, `tools:register`, `model-config`, `commands:run`, and `session:subjectToken` (socket-only, always token-authenticated, :569-571). |
| User session | `PUT /v1/session` with `source`/`external_id` resolves the identity from the verified bundle. A linked identity's bundle `subject_token` becomes the session's subject evidence (`runtime/socket_authorize.go:839-848`). The caller never supplies identity or a token. |
| `cli` source | Uses the OS-keychain CLI login token through `SessionKeychain` (`runtime/socket_authorize.go:170-177,762-774`). `SetKeychain` (:337) has **no production caller**, so `source: cli` always answers `cli source not available`. |
| Service-principal session | Selected by ID or name. Caller identity fields, including `subject_token`, are rejected (`runtime/socket_authorize.go:706-711`). The subject is built from the bundle principal and its token (:733). |
| Bundle identity tokens | Principal tokens are `json:"-"` in the payload (`pkg/policybundle/bundle.go:79-96`) and strictly validated (:294). The PDP strips `Subject.Token` before evaluation (`pkg/pdp/pdp.go:164`). |
| Bundle on disk | The raw bundle bytes, including every embedded `subject_token`, are persisted to `KEI_RUNTIME_STATE_DIR/policy/bundle.json`, mode 0600 in a 0700 directory (`pkg/policybundle/store.go:74-80,116,510`). |
| Credential release (I11) | One call at session start, with `Authorization: Bearer <runtime token>` and `X-Kei-Subject-Token` (`internal/credrelease/client.go:115-130`; per connector: `internal/credrelease/connector.go:56-70`). Redirects are not followed (`internal/credrelease/client.go:84`). Values stay in session memory, and `RLIMIT_CORE=0` (`serve.go:62`). |
| `POST /v1/credentials:release` | Releases a session-held connector credential after a fresh allow, bound to tool, connector, capability and resource. `on_behalf_of` is audit-only (`docs/unix-socket.md:300-328`; `runtime/socket_authorize.go:1144-1150`). |
| `POST /v1/session:subjectToken` | Opt-in through `KEI_EXPORTABLE_SERVICE_PRINCIPALS` (`config.go:40-42,100-110`). It returns the principal's raw `subject` JWT (up to ~8 h) with `Cache-Control: no-store`, and writes one audit record per issue (`runtime/socket_subject_token.go:99-155`). The documented threat model says a handed-out token cannot be revoked (`docs/unix-socket.md:392-400`). The owner decided on this route (wiki decision "Owner 2026-11-01: seed token via … POST /v1/session:subjectToken"). |
| Model config | `GET /v1/model-config` returns profile metadata. The runtime's cloud identity reads the key from `secret_ref` (`serve.go:270,323-324`). No Kei token is involved. |
| Token exchange | Absent. There is no `act`, `may_act` or token type URI. `on_behalf_of` is attribution only. |

## 4. ADR context (kei)

- **ADR-009** (`kei:docs/adr/009-transport-authentication.md:52-75`): one
  authentication header per layer. The service secret travels only in
  `X-KEI-API-Key`.
- **ADR-011** (`kei:docs/adr/011-tenant-side-proxy-data-plane.md:52-67`):
  the catalog distributes policy and never receives credentials. kei-proxy is
  the local PDP and PEP.
- **ADR-019** (`kei:docs/adr/019-resource-oriented-apis-and-a-uniform-cli.md:62-63`):
  custom methods are spelled `:verb`.
- **ADR-032** (`kei:docs/adr/032-identity-service-ownership.md:125,169-199,348-364`):
  the identity service mints every Kei user token. It also defines the
  subject-token claims and the 8 h maximum.
- **ADR-033/034:** the gateway is the authentication boundary for I11. The
  subject token travels in `X-Kei-Subject-Token`, and credentials are
  released at session start.
- **ADR-039** (`kei:docs/adr/039-decision-only-runtime-and-independent-payloads.md:52-53`):
  the runtime decides and passes through. Kei never calls providers.
- **ADR-040/041** (`kei:docs/adr/041-acting-as-a-service-principal.md:44-51`):
  a service principal is bound to an (installation, agent) pair.
  `invoking_subject` is `user:` or `service_principal:`, and `on_behalf_of`
  is nullable and typed. The principal token's wire format and claims are
  still marked **OPEN** (rows 4-5).
- **ADR-036:** an Entra OBO amendment for the runtime (kei#941, 2026-10-15)
  is not on kei `main`. Its runtime work (HAI-669) was cancelled on
  2026-10-15, when the owner decided against Power BI support.

## 5. Gaps and risks

Severity scale:

- **High:** token theft or misuse beyond its intended scope is plausible today.
- **Medium:** a standards gap that blocks interoperability or weakens defence in depth.
- **Low:** hygiene.

| # | Finding | Against | Severity |
|---|---|---|---|
| A1 | Every bundle carries a bearer `subject` JWT, valid up to 8 h, for **every** linked identity in the workspace. Every installation in the workspace receives the bundle and persists it to disk. Compromising one runtime host yields usable subject tokens for all workspace users. (`catalog:internal/runtime/policy_bundle.go:424-475`, `catalog:pkg/database/policy_bundle_builder.go:315-338`, `pkg/policybundle/store.go:510`) | RFC 8693 §5 (short lifetimes, least privilege); RFC 6819 §5.1.5.3 | **High** |
| A2 | Subject tokens are bound to a workspace, not to an installation or agent. I11 and `runtime:authenticate` accept any runtime token from the same workspace (`catalog:internal/runtimeauth/authenticator.go:132-135`, `bridge:internal/connectors/resolve_auth.go:113-120`). Together with A1, one installation can release another user's connector credentials through I11. RFC 8693 `may_act` exists to express "who may present this". | RFC 8693 §4.4 | **High** |
| A3 | `POST /v1/session:subjectToken` exports a raw, broad-audience (`kei-gateway`) principal token, valid up to ~8 h, that cannot be revoked once issued (`docs/unix-socket.md:392-400`). The analytics sidecar accepts it, and so does the gateway/I11. A token scoped to one audience would serve the same need. | RFC 8693 §2.1 `audience`/`resource`; RFC 9068 §4 | Medium (opt-in, allow-listed) |
| A4 | There is no delegation semantics. Tokens never say which agent acts for the user: no `act`, and `on_behalf_of` is audit-only. Downstream services cannot tell the user from the agent. | RFC 8693 §1.1, §4.1 | Medium |
| A5 | There is no standard token exchange. The I11 exchange is proprietary: no `grant_type`, no token type URIs, no `issued_token_type`, and errors are not in RFC 8693 §2.2.2 form. No downstream API can obtain a Kei-issued, audience-restricted token for a session. | RFC 8693 §2 | Medium |
| A6 | `access` tokens have no `aud`, `jti`, `client_id` or `scope`, the header `typ` is `JWT`, and verifiers skip the audience check for `access` (`bridge:internal/tokensign/signer.go:40-45`, `bridge:internal/tokensign/claims.go:115-139`). Any service that accepts `typ=access` accepts every access token. | RFC 9068 §2.1-2.2, §4 | Medium |
| A7 | The ID token `aud` is the fixed value `kei-client`, not the requesting `client_id`. There is no `azp` or `auth_time`, and `nonce` is optional (`bridge:internal/oidcprovider/oidc.go:28,220,464`). | OIDC Core §2, §3.1.3.7 | Medium |
| A8 | Discovery lacks `authorization_endpoint`, `token_endpoint` and `userinfo_endpoint`. These are REQUIRED by OIDC Discovery §3, and RFC 8414 metadata is absent. | OIDC Discovery §3; RFC 8414 §2 | Low |
| A9 | `jti` is generated but nothing stores or checks it. There is no revocation or introspection endpoint, and removing a signing key is the only kill switch. | RFC 7519 §4.1.7; RFC 7009/7662 | Medium (matters once exchanged tokens exist) |
| A10 | Runtime tokens never expire (`catalog:pkg/database/harness_keys.go:210-216`). As the client credential of any future exchange, they are long-lived. | RFC 6819 §5.1.5.3 | Medium |
| A11 | `observe` modes for client authentication and PKCE let failures through (`bridge:internal/oauthclient/auth.go:131-135`, `bridge:internal/oauthclient/pkce.go:134-138`). | RFC 9700 §2.1.1 | Low (migration aid; must be off for any exchange client) |
| A12 | No refresh grant exists (HAI-945 is approved). Any refresh-token response to an exchange must stay out of scope. | RFC 8693 §2.2.1 | Low |
| A13 | The runtime's `source: cli` session path is dead code: `SetKeychain` is never called (`runtime/socket_authorize.go:337`). That matches the owner's goal of no runtime token on dev machines (wiki handoff "I-1 ack: Pi governance blocker"), but the dead path still documents a keychain-token design. | Hygiene | Low |
| A14 | The device-flow CLI token lifetime is documented as one hour (`bridge:docs/api/identity-v1.md:229`), but the code default is 8 h (`bridge:cmd/oidc-bridge/main.go:146`). | Contract drift | Low |
| A15 | When the bundle is already past `not_after`, the subject-token TTL resets to the 8 h maximum instead of failing (`catalog:internal/runtime/policy_bundle.go:442-444`). | Fail closed | Low |

What is already right, and must be kept:

- ES256 only, `kid`-based rotation, a strict `typ` allow-list, and `crit`
  rejected.
- I11 fails closed and follows no redirects.
- The runtime never accepts caller-supplied identity or tokens.
- Credentials stay in session memory and are never logged.
- The subject-token export is opt-in, allow-listed and audited.
