# Runtime policy bundles

## Contents

- [Bootstrap and state](#bootstrap-and-state)
- [Validation and evaluation](#validation-and-evaluation)
- [Deny-overrides evaluation](#deny-overrides-evaluation)
  - [Worked example](#worked-example)
  - [Which bundles carry deny-overrides](#which-bundles-carry-deny-overrides)
- [A bundle the runtime cannot parse](#a-bundle-the-runtime-cannot-parse)
- [The harness kind registry (`harness_kinds`)](#the-harness-kind-registry-harness_kinds)

`kei-proxy` enforces unsigned canonical `kei.policy-bundle/v2` JSON bundles locally. The runtime fetches the current bundle over a validated HTTPS control-plane connection using the installation runtime token. It validates the response media type and canonical closed schema before activation. The canonical v2 schemas are vendored under `docs/contracts`. A `kei.policy-bundle/v1` bundle is no longer accepted: it is rejected as unsupported with an error that names the upgrade (the catalog must deliver a `kei.policy-bundle/v2` bundle), and the runtime has no v1 evaluator.

## Bootstrap and state

Set `KEI_RUNTIME_TOKEN`, `KEI_RUNTIME_CONTROL_PLANE_URL`, and a writable `KEI_RUNTIME_STATE_DIR`. The default depends on the operating system:

- **macOS**: `$HOME/Library/Application Support/kei-proxy`
- **Linux** (running as root): `/var/lib/kei-proxy`
- **Linux** (non-root, with `$XDG_STATE_HOME` set): `$XDG_STATE_HOME/kei-proxy`
- **Linux** (non-root, no `$XDG_STATE_HOME`): `$HOME/.local/state/kei-proxy` (the XDG default state home)

The control-plane URL must be an HTTPS origin without userinfo, path, query, or fragment. Requests use the installation bearer token, follow no redirects, and rely on Go's standard TLS certificate and hostname validation. HTTP is permitted only for loopback test/development servers; non-loopback HTTP is rejected.

The bundle endpoint returns the canonical JSON body with content type `application/vnd.kei.policy-bundle.v2+json`, a strong ETag exactly `"sha256:<lowercase hex digest of exact response bytes>"`, and a monotonically increasing bundle-version header. The runtime checks the exact raw-byte digest against the ETag before schema validation, then checks the header version against the validated payload before atomically activating it. No signature, signing key, TOFU state, or signing-key endpoint is required.

The state directory is mode `0700`; `policy/bundle.json` and `policy/state.json` are atomically written with mode `0600`, protected by a per-state-directory exclusive lock. Raw bundle bytes are persisted unchanged and revalidated before use; their stored digest must still match. A missing, malformed, expired, audience-mismatched, replayed, or unsupported bundle denies; there is no older-bundle or built-in allow fallback. The runtime does not load legacy envelopes or key files.

The rollback/replay watermark (`highest_bundle_version` in `policy/state.json`) is scoped to the bundle audience: installation ID, org ID, and workspace ID together. For the same audience, a candidate with a version lower than or equal to the watermark is rejected as a rollback or replay. When a machine switches installations (for example, `kei setup` with a new runtime token), the first valid candidate for the new audience is treated as a new installation: the previous installation's `state.json` and `bundle.json` are renamed into `policy/archive/<UTC timestamp>-<old installation_id>/` (never deleted), and the new bundle is accepted with its own watermark. A candidate that fails validation leaves the previous installation's state in place.

The `runtime bootstrap`, `runtime heartbeat`, and `serve` startup paths fetch and activate bundles. `kei-proxy policy sync --force` explicitly requests a newly issued bundle via the runtime-token-scoped refresh API; it does not fall back to an older cached bundle on publication failure. One-shot `authorize` reads only persisted state. Periodic refresh scheduling is intentionally deferred to HAI-290/T51. A failed candidate never replaces the active bundle; a valid active bundle may be enforced until its `not_after`. 401/403 responses revoke the installation, remove the active bundle, and deny. One-shot `authorize` resolves the human subject online (`POST /api/v1/runtime/subject-attributes:resolve` at `KEI_RUNTIME_CONTROL_PLANE_URL`) when the tool is bound to a connector capability or a policy reached for the call matches on subject attributes (any `src_pattern` other than `*` or `agent:`). A tool service alone does not require subject resolution. Any other tool, such as `web_search` under a `*` or `agent:` policy, is decided from the bundle with no subject and no subject-resolution request. When resolution is needed, unavailable or invalid subject data denies with `subject_resolution_unavailable` before any policy is evaluated.

## Validation and evaluation

Before activation, the runtime checks the canonical schema, duplicate JSON keys, issuer, installation/org/workspace audience, policy revision, strictly increasing bundle version, issued-at time, hard expiry, validity-window limits, and supported policy match semantics. Invalid candidates do not displace an already active bundle.

The runtime checks the tool and its canonical action from the verified policy bundle, not a caller-selected action. Service and connector capability metadata are also read from that bundle.

Policy matching follows `kei.match/v2`. Unless a bundle declares `deny_overrides` (next section), a v2 bundle's `evaluation.precedence` is `priority_desc`, `deny_before_permit`, `policy_id_asc`: the matching policy with the highest priority decides, a deny beats a permit of equal priority, `policy_id` ascending breaks the remaining ties, and no match denies. Subject memberships come from the bundle's identity snapshot. Approval flags do not act as per-call tokens. The next section describes the replacement for this ordering, which `kei-proxy` accepts from 0.6.0.

A local decision does not move provider payloads, results, or credentials to the catalog. Credential lookup/provider execution remains tenant-side and occurs only after a local allow.

## Deny-overrides evaluation

Deny-overrides is accepted from **`kei-proxy` 0.6.0**: `proxy-v0.6.0` is the first release whose v2 bundle schema and evaluator accept it (checked by running its schema and evaluator tests at the tag). A release before 0.6.0, including `proxy-v0.5.0`, rejects a bundle that declares it, because its closed v2 schema pins `precedence` to the legacy list; it rejects the whole bundle, not just the field (see [A bundle the runtime cannot parse](#a-bundle-the-runtime-cannot-parse)). The catalog sends it only to an installation whose last heartbeated `kei-proxy` version is 0.6.0 or later, and only while the `POLICY_BUNDLE_V2_DENY_OVERRIDES` fleet switch is on (it is off by default); every other installation keeps the legacy ordering described above.

Under deny-overrides the runtime collects every enabled policy that matches the request, then decides:

1. If any matching policy is a deny, the call is denied. It does not matter how many permits also match, and it does not matter where the policies sit in the bundle.
2. Otherwise, if any matching policy is a permit, the call is allowed.
3. If no policy matches, the call is denied (fail closed). Deny is the bundle's `evaluation.default`, and the runtime requires it.

Priority is not read. The only tie-break is the policy id in ascending order, which decides which matching policy is reported as the decider when several deny or several permit; it never changes the outcome. The comparator is `policy.Precedence` in `kei-connector-contracts` (the evaluator is pinned to a contracts release that includes it; see `go.mod`).

Policies name only groups as sources: `group:<name>`, `autogroup:member` or `autogroup:admin`. A policy never names an email address.

### Worked example

A bundle holds two enabled policies for the fictional group `engineering`. Shell destinations are matched token by token as an argv prefix, so `shell:git` covers every `git` command and `shell:git push` covers every `git push` command.

| Policy | Source | Destination | Action |
|---|---|---|---|
| `p-permit-git` | `group:engineering` | `shell:git` | permit |
| `p-deny-push` | `group:engineering` | `shell:git push` | deny |

A member of `engineering` runs three commands:

| Command | Policies that match | Decision | Why |
|---|---|---|---|
| `git push origin main` | `p-permit-git` and `p-deny-push` | **deny** (`policy_deny`, decided by `p-deny-push`) | A matching deny wins over the matching permit, in either order and at any priority. |
| `git status` | `p-permit-git` only | **allow** (decided by `p-permit-git`) | Only a permit matches. |
| `make test` | none | **deny** (`no_matching_policy`) | No policy matches, so the call fails closed. |

Under the priority ordering that releases before 0.6.0 use, and that a bundle without `deny_overrides` still uses, the first row depends on the two policies' priorities: a permit with a higher priority than the deny would allow the push. That is the difference deny-overrides removes.

### Which bundles carry deny-overrides

A bundle declares it in the policy set:

| Bundle | Where it is declared | Today's validators |
|---|---|---|
| `kei.policy-bundle/v2` | `deny_overrides` is an entry of `policy_set.evaluation.precedence` | From `kei-proxy` 0.6.0 the vendored `policy-set-v2.schema.json` accepts `precedence` as either `priority_desc`, `deny_before_permit`, `policy_id_asc` or exactly `deny_overrides`, and the runtime evaluates a bundle that declares it with deny-overrides. Any other `precedence` fails validation, and releases before 0.6.0 pin `precedence` to the legacy list and reject a bundle that declares `deny_overrides`. |

The evaluator in `kei-connector-contracts` understands the declaration. The runtime accepts the v2 declaration from 0.6.0; the v1 `order` value went with the v1 bundle, which the runtime rejects. A runtime older than 0.6.0 must not be sent a bundle that declares it.

The catalog protects older runtimes with a version gate: it leaves a new bundle field out unless the installation's last heartbeated `kei-proxy` version is at least the first release that accepts it, and an installation that has not reported a version gets the oldest shape. The deny-overrides gate in the catalog is `0.6.0`, the first release that accepts it, and it sits behind the `POLICY_BUNDLE_V2_DENY_OVERRIDES` fleet switch, which is off by default.

## Harness condition: `when`

A `kei.policy-bundle/v2` `harness_policies` row may carry an optional `when: {"harness": "<kind>"}` member (ADR-038 D-6). The rule applies only to calls made through that harness kind; a row without `when` applies to every kind. The harness is context, not identity, so it narrows a rule and never grants one.

- A rule whose `when` does not match the call's harness kind does not apply, and a call whose kind is unknown never matches a `when`. A permit that never applies leaves the call to the default deny.
- It composes with deny-overrides: a deny whose `when` matches still beats every matching permit, and a deny whose `when` does not match is not considered.
- Only `harness_policies` rows accept it. `checks` and `tool_policies` rows are not given the harness kind, so the closed schema keeps rejecting the member there.
- The schema is closed. A runtime that predates `when` rejects the whole bundle, so the catalog emits the member only to runtimes at or above the first release that accepts it.

## A bundle the runtime cannot parse

The v2 bundle schema is closed: an unknown field, or a value outside a pinned set, is a validation failure, not something the runtime skips. A bundle that fails validation is never activated and never replaces the active bundle, which keeps being enforced until its `not_after`. With no active bundle, every call denies.

| Failure | Stored state | Denial reason | Effect |
|---|---|---|---|
| Unknown field, unknown bundle schema id, unsupported subject-resolution mode, unsupported evaluation order, or a harness kind outside the registry | `unsupported` | `policy_bundle_unsupported` | The candidate is dropped. A held bundle stays; with none, calls deny. |
| Any other validation failure (schema value mismatch, audience mismatch, rollback or replay, expired, bad validity window) | `invalid` | `policy_bundle_invalid`, or `policy_bundle_expired` for an expired one | Same: nothing replaces a held bundle. |

The state is recorded only while the runtime holds no bundle. `policy/state.json` carries the reason code, and `kei-proxy` logs `policy bundle refresh failed; the active bundle stays until it expires` (see [policy-refresh.md](policy-refresh.md)). This is why the catalog adds a new field only for runtimes whose version it knows accepts it: an older runtime would reject the whole bundle, not just the field.

## The harness kind registry (`harness_kinds`)

The v2 bundle may carry `harness_kinds`, a registry of the harness kinds that `harnesses[].kind` may name. Each entry has:

| Field | Meaning |
|---|---|
| `kind` (required) | The kind id, `^[a-z][a-z0-9_]{0,31}$`. |
| `gateable` (required) | Whether the kind's calls can be gated. |
| `short_name` | How the kind's hooks name it. |
| `tool_prefix` | The prefix of the kind's tool names. |
| `shell_tool` | The tool that carries a shell command line. |
| `decides_via` | `pdp` (the `kei-proxy` local policy decision point) or `native` (a rendered native allowlist). Absent keeps the built-in meaning: `custom` and `pi` decide via the PDP. |
| `native_tools` | `tool_name` and `native_name` pairs for the kind's native tools. |

With no registry, only the built-in kinds are valid and behavior is unchanged. With a registry, the runtime validates every `harnesses[].kind` against it, and a kind it does not list makes the bundle unsupported.

The runtime accepts the field from **`kei-proxy` 0.5.0** (`proxy-v0.5.0`); `proxy-v0.4.0` and earlier reject a bundle that carries it, the whole bundle, not just the field. The catalog side is not merged yet: the catalog does not emit `harness_kinds` today. When it does, it will be only behind a fleet switch that is off by default and a minimum-version gate. Do not enable that switch before every installation that fetches bundles runs 0.5.0 or later.
