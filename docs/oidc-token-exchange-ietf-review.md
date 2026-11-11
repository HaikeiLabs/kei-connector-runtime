# Token exchange vs the IETF delegation drafts: delta list

Status: **review**, 2026-11-11. Docs only. No spec decisions are made here;
this file reports differences so the owner and Colin can decide HAI-977
(Q1–Q7) and HAI-986 (node-to-node chained exchange).

Inputs:

- [oidc-token-exchange.md](oidc-token-exchange.md) — the spec (§1–§12,
  questions Q1–Q7).
- [oidc-token-exchange-audit.md](oidc-token-exchange-audit.md) — the as-built
  audit (findings A1–A15).

## 0. Method and limits

- Drafts were fetched by the orchestrator from the IETF datatracker on
  2026-11-11 as **abstracts plus short mechanics summaries**. The full draft
  text was not read by this review. Everything in a "Draft" column marked
  *(orch summary)* is the orchestrator's wording, not quoted draft text; no
  draft section numbers are cited because none were verified.
- Each draft is cited by name-revision. Revision numbers are as fetched on
  2026-11-11.
- The datatracker search found **no other current OAuth WG or individual
  draft on AI-agent / on-behalf-of delegation** beyond the four below.
  Re-check the datatracker (new revisions, new drafts) before any HAI-977
  decision is finalized.

Drafts compared:

| Cited as | Full name | Status at fetch |
|---|---|---|
| identity-chaining-17 | draft-ietf-oauth-identity-chaining-17, *OAuth Identity and Authorization Chaining Across Domains* | WG draft, updated 2026-08-21, expires 2027-01-20 |
| transaction-tokens-11 | draft-ietf-oauth-transaction-tokens-11, *Transaction Tokens* | WG draft, updated 2026-08-21, expires 2027-01-31 |
| id-jag-06 | draft-ietf-oauth-identity-assertion-authz-grant-06, *Identity Assertion JWT Authorization Grant* (ID-JAG; Cross App Access / XAA; used by Okta) | WG draft, updated 2026-10-31, expires 2027-05-04 |
| ai-agents-obo-02 | draft-oauth-ai-agents-on-behalf-of-user-02, *OAuth 2.0 Extension: On-Behalf-Of User Authorization for AI Agents* | Individual draft, **not WG-adopted, EXPIRED** (last updated 2026-02-27) |

## 1. identity-chaining-17

Preserves identity and authorization information across trust domains using
OAuth 2.0. A JWT authorization grant, obtained through an intra-domain OAuth
2.0 Token Exchange, is used for the cross-domain acquisition of an access
token. Identity and authorization information is chained by being carried in
the artifacts exchanged at each step, and multiple domains are chained by
repeating the same protocol (abstract). Mechanics *(orch summary)*: the
client makes an RFC 8693 token-exchange request to its home AS with an
audience naming the other domain's AS; the home AS returns a JWT
authorization grant, which the client presents to the other domain's AS as an
RFC 7523 jwt-bearer grant to obtain the access token. The home AS may add,
remove or change claims during transcription. The `act` claim carries
delegation and `may_act` constrains it through the grant.

| Aspect | Our spec (section ref) | Draft *(orch summary)* | Delta | Suggested change | Informs |
|---|---|---|---|---|---|
| Protocol shape | One hop: kei-proxy exchanges the session subject JWT for a final, audience-restricted Kei access token (§3.1, §4) | Two hops: RFC 8693 exchange at the home AS yields a JWT **authorization grant**, presented onward as an RFC 7523 jwt-bearer grant | Our exchange mints a final token; the draft's per-hop output is an intermediate grant | None for phase 1–2 (single issuer, single domain). If HAI-986 proceeds, consider making hop N's output a grant for hop N+1 | **HAI-986**, Q6 |
| Trust domain | One issuer (kei-oidc-bridge); audience must be a registered Kei resource (§4, §6) | Cross-domain: the exchange's `audience` names the remote domain's AS | The draft's core problem (cross-domain trust) does not arise for us | Keep the registered-audience rule; revisit only if Kei federates with a second issuer | Q1, HAI-986 |
| `act` | `act.sub` = the installation's agent, derived from the runtime token (§5, Q3) | `act` is carried in the artifacts exchanged at each step | Same concept, different origin: we derive the actor, the draft transports it | Keep the derived actor (the Q3 lean) | Q3, Q6 |
| `may_act` | Planned in phase 3 as subject-token hardening (Q6, §12) | `may_act` constrains who may act **through the grant chain** | In the draft, `may_act` is the chaining control itself, not optional hardening | If HAI-986 is planned, `may_act` per hop becomes load-bearing and phase 3 stops being optional | Q6, **HAI-986** |
| Claims | Fixed profile (§5); the STS re-checks audience/scope but rewrites nothing | The home AS may add, remove or change claims at transcription | The draft explicitly allows claim rewriting between hops; we never rewrite | Out of scope for phase 1–3; note the catalog (not the STS) is our only sanctioned claim source | HAI-986 |
| Client authentication | Runtime installation token as client credential (§2, §4) | A general OAuth client presenting the grant to the next AS | Our client is always a Kei runtime installation | None | — |

## 2. transaction-tokens-11

Txn-Tokens maintain and propagate user identity, workload identity and
authorization context through the call chain inside a trusted domain, for
external requests or requests started inside the trust domain (abstract).
Mechanics *(orch summary)*: a Transaction Token Service issues short-lived
signed JWTs (`typ txntoken+jwt`) via a token-exchange-style request; claims
include `txn` (transaction id), `sub`, `aud` = the trust domain, `scope`,
`tctx` (transaction context), `rctx` (requester context) and `req_wl`
(requesting workload). Txn-Tokens **replace external access tokens inside
the trust domain and are not sent outside it**; each workload may request a
replacement Txn-Token as the call moves along the chain.

| Aspect | Our spec (section ref) | Draft *(orch summary)* | Delta | Suggested change | Informs |
|---|---|---|---|---|---|
| Where the token travels | Released to the harness, which calls the downstream API directly — including customer APIs that federate with Kei (§1, §3.1) | Stays **inside** the trust domain; replaces external access tokens for internal calls and is not sent outside | Our token is meant to cross to resource servers; Txn-Tokens are deliberately internal-only | Keep our model for external APIs; consider Txn-Tokens later for internal Kei-to-Kei calls (gateway, analytics) | HAI-986 |
| Chaining mechanism | Nested `act` not produced in phase 1–3; subagent hops keep audit fields (`invoking_subject`, span IDs) (§3.3, §5) | Each workload requests a **replacement** Txn-Token per hop — no nested `act` | The draft chains by per-hop re-issuance rather than nesting actors | For HAI-986, per-hop re-issuance is a second draft-backed alternative to nested `act` | **HAI-986**, Q6 |
| Chain context | None in the token; audit carries `jti`, span IDs and `policy_reason` (§9) | `txn`, `tctx`, `rctx` claims put chain context in the token | We keep correlation in audit only; the draft puts it in the token | Option for HAI-986: carry a transaction id so downstream Kei services can correlate the chain | HAI-986 |
| Workload identity | `act.sub` = agent + `client_id` = installation (§5) | `req_wl` (requesting workload) claim | `req_wl` plays the role of our `act`/`client_id` pair | No change; name any future workload-claim addition consistently | HAI-986 |
| Audience | Exactly one registered resource, REQUIRED (§4) | `aud` = the trust domain | Ours is per-resource (least privilege); the draft's is per-domain | Keep per-resource; flag the difference if we ever issue domain-wide tokens | — |
| Lifetime | 300 s default, 900 s max, never past subject `exp` (§5, §8) | Short-lived signed JWTs | Aligned | — | Q5 |

## 3. id-jag-06 (ID-JAG / Cross App Access)

An application uses an identity assertion to obtain an access token for a
third-party API by going through an IdP that the downstream resource
authorization server already trusts for SSO, using OAuth 2.0 Token Exchange
(RFC 8693) and the JWT Profile for OAuth 2.0 Authorization Grants (RFC 7523)
(abstract). Mechanics *(orch summary)*: the client exchanges the user's ID
token (or a SAML assertion) at the enterprise IdP with
`requested_token_type = urn:ietf:params:oauth:token-type:id-jag`,
`audience` = the resource AS issuer, plus `resource` and `scope`; the IdP
applies enterprise policy and returns an ID-JAG JWT
(`typ oauth-id-jag+jwt`; `iss` = IdP, `sub`, `aud` = resource AS, `client_id`,
`jti`, `exp`, `resource`, `scope`); the client presents the ID-JAG to the
resource AS as a jwt-bearer grant and gets an access token. This gives the
enterprise IdP central control over which apps reach which APIs; SAML-only
orgs can use a SAML assertion as the subject token. This is what Okta ships
as Cross App Access (XAA).

| Aspect | Our spec (section ref) | Draft *(orch summary)* | Delta | Suggested change | Informs |
|---|---|---|---|---|---|
| `subject_token` | A Kei `subject` JWT (`typ=subject`, `aud ∋ kei-gateway`) (§4) | The user's **ID token** (or a SAML assertion) | We exchange an internal subject token, not an identity token | None now; accepting third-party ID tokens as subjects would be new ADR-036-territory work | Q1 (what the registry binds), ADR-036 |
| `requested_token_type` | Only `urn:ietf:params:oauth:token-type:access_token` is accepted; anything else is `invalid_request` (§4) | `urn:ietf:params:oauth:token-type:id-jag` — the exchange outputs a **grant**, not a token | The ecosystem now has a second standardized exchange output | Note as a phase-3+ option: Kei-issued ID-JAGs for downstream ASes (e.g. Entra) instead of direct OBO | **HAI-986** |
| Central policy point | Catalog registry (`exchange-audiences` / connector kind) + STS re-check (§6, Q1) | The enterprise IdP applies enterprise policy centrally before issuing the ID-JAG | Same architectural role: one central place decides which client reaches which API | Supports the Q1 connector-kind lean: reuse bindings/descriptors as our enterprise-policy point | Q1 |
| `audience` | A registered Kei resource, exactly one (§4) | The downstream **resource AS's issuer** | Ours names a resource; ID-JAG names the next AS | For HAI-986, when the downstream is another AS, `audience` = that AS's issuer | HAI-986, Q1 |
| Adoption | Not implemented; ADR-036 design text only; owner deferred ID-JAG on 2026-10-18 (audit §1, §4) | Production reality (Okta Cross App Access) | Our 2026-10-18 deferral now has a shipped, standardized analogue | Revisit the deferral as part of HAI-977/HAI-986 with this new information | — |

## 4. ai-agents-obo-02 (individual, EXPIRED)

Lets AI agents obtain access tokens to act on behalf of users. Adds a
`requested_actor` parameter to authorization requests (identifying the agent
needing delegation) and an `actor_token` parameter to token requests
(authenticating the agent during the code exchange). Can be started by a
resource server challenge, so user consent is obtained when access is
attempted (abstract). Status: individual draft, not WG-adopted, expired
(last updated 2026-02-27). The datatracker search found no other current
draft on AI-agent / on-behalf-of delegation.

| Aspect | Our spec (section ref) | Draft *(orch summary)* | Delta | Suggested change | Informs |
|---|---|---|---|---|---|
| Actor presentation | Actor derived from the runtime token; `actor_token` MUST be absent (§4, Q3) | `actor_token` on the token request authenticates the agent | This draft is the explicit-actor alternative that our Q3 rejects | Keep the derived actor; the draft is expired and carries no WG consensus | Q3 |
| Consent | No user-facing consent stage; catalog policy decides (§6) | `requested_actor` in the authorization request; a resource-server challenge starts the flow so consent happens at access time | The draft builds delegation consent into the OAuth flows; our runtime-only exchange has no such stage | If Kei ever exposes user-facing delegation consent, revisit; no phase 1–3 impact | Q4 |
| Status | — | Expired individual draft | No WG adoption | Treat as a signal, do not design to it | — |

## 5. Recommendations for HAI-977 (options, not decisions)

- **Q1 (audience registry).** Options unchanged: (a) new catalog resource
  `exchange-audiences`, or (b) connector kind `kei_resource` with the
  audience in the descriptor. id-jag-06's central-enterprise-policy role
  matches option (b)'s reuse of bindings/descriptors as the enterprise policy
  point. identity-chaining-17 shows the registry may eventually need to name
  **AS issuers**, not just resource URIs, if cross-AS chaining ever lands.
  No decision.
- **Q2 (public endpoint).** The spec lean (runtime-only AIP method) is
  consistent with everything fetched. Both WG drafts assume a standard token
  endpoint reachable by general clients — so Q2 would have to flip if Kei
  ever accepts inbound exchanges from third-party clients (ID-JAG inbound).
  No decision.
- **Q3 (actor token).** The spec lean (derived actor) is supported: the only
  draft endorsing a presented `actor_token` is an expired individual draft;
  both WG drafts carry/derive `act` instead. No decision.
- **Q4 (impersonation).** The spec lean (no tokens without `act`) is
  supported: no fetched draft endorses unattributed tokens; the AI-agent
  draft adds consent around delegation rather than removing the actor. No
  decision.
- **Q5 (revocation).** No fetched draft forces introspection for short-lived
  tokens; transaction-tokens-11 relies on short lifetimes. Option: stay
  expiry-only at the 300 s default and revisit only if the lifetime cap goes
  beyond 900 s. No decision.
- **Q6 (bundle token fan-out / `may_act`).** identity-chaining-17 treats
  `may_act` as the per-hop chaining control and transaction-tokens-11 chains
  by per-hop re-issuance. If HAI-986 is on the roadmap, `may_act` per
  session/hop becomes load-bearing, which strengthens the per-session minting
  option over bundle fan-out (the spec already flags this as the most
  valuable hardening; cross-repo cost stands). No decision.
- **Q7 (retire `session:subjectToken`).** Unaffected by the drafts; both WG
  drafts are consistent with audience-restricted exchanged tokens replacing
  broad internal ones. No decision.

**HAI-986 note (node-to-node chained exchange).** Two draft-backed patterns
exist: (i) grant-per-hop — RFC 8693 exchange yields a JWT authorization grant
presented onward via RFC 7523 (identity-chaining-17); (ii) per-hop
replacement — each workload re-requests a fresh short-lived token as the call
moves along (transaction-tokens-11). Neither uses nested `act` chains. Our
spec currently lacks both `may_act` per hop and an in-token correlation id;
either pattern would add those two things.

## 6. Implications for connectors

- **`credential_source: kei_token_exchange`.** The per-connector descriptor
  field in the kei-connector-contracts `policy-set-v2.schema.json`, with
  `exchange: {audience, resource?, scopes[]}` (spec §7). None of the four
  drafts conflicts with a per-connector descriptor carrying audience/scope
  server-side; id-jag-06's enterprise-policy role actively supports keeping
  audience and scope in the verified bundle descriptor, never
  caller-supplied (§6). The contracts release, catalog pin and runtime pin
  still have to move together.
- **HAI-574 (Power BI audience issue).** A Kei-minted exchanged token carries
  a Kei-registered audience (§4); a resource that only accepts tokens minted
  by its own issuer (Entra/Power BI) cannot accept it. That
  exchange-into-provider-tokens step stays out of scope per the spec's
  non-goals (§1) and ADR-036, and the owner declined Power BI runtime
  support on 2026-10-15 (audit §4). Of the fetched drafts, **id-jag-06 is the
  one standardized precedent** for an Entra-trusting provider to accept a
  third-party IdP's grant (Cross App Access), so it is the relevant precedent
  if HAI-574 is ever revisited via XAA rather than Entra OBO.
