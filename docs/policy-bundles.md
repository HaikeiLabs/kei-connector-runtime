# Runtime policy bundles

## Contents

- [Bootstrap and state](#bootstrap-and-state)
- [Validation and evaluation](#validation-and-evaluation)
- [Deny-overrides evaluation](#deny-overrides-evaluation)
  - [Worked example](#worked-example)
  - [Which bundles carry deny-overrides](#which-bundles-carry-deny-overrides)
- [A bundle the runtime cannot parse](#a-bundle-the-runtime-cannot-parse)
- [The harness kind registry (`harness_kinds`)](#the-harness-kind-registry-harness_kinds)

`kei-proxy` enforces unsigned canonical `kei.policy-bundle/v1` JSON bundles locally. The runtime fetches the current bundle over a validated HTTPS control-plane connection using the installation runtime token. It validates the response media type and canonical closed schema before activation. The canonical schemas and policy fixtures are vendored byte-for-byte and their hashes remain pinned in tests. Kei PR #693 is merged; the updated root schema describes the raw unsigned canonical payload and removes signing-only definitions.

## Bootstrap and state

Set `KEI_RUNTIME_TOKEN`, `KEI_RUNTIME_CONTROL_PLANE_URL`, and a writable `KEI_RUNTIME_STATE_DIR`. The default depends on the operating system:

- **macOS**: `$HOME/Library/Application Support/kei-proxy`
- **Linux** (running as root): `/var/lib/kei-proxy`
- **Linux** (non-root, with `$XDG_STATE_HOME` set): `$XDG_STATE_HOME/kei-proxy`
- **Linux** (non-root, no `$XDG_STATE_HOME`): `$HOME/.local/state/kei-proxy` (the XDG default state home)

The control-plane URL must be an HTTPS origin without userinfo, path, query, or fragment. Requests use the installation bearer token, follow no redirects, and rely on Go's standard TLS certificate and hostname validation. HTTP is permitted only for loopback test/development servers; non-loopback HTTP is rejected.

The bundle endpoint returns the canonical JSON body with content type `application/vnd.kei.policy-bundle.v1+json`, a strong ETag exactly `"sha256:<lowercase hex digest of exact response bytes>"`, and a monotonically increasing bundle-version header. The runtime checks the exact raw-byte digest against the ETag before schema validation, then checks the header version against the validated payload before atomically activating it. No signature, signing key, TOFU state, or signing-key endpoint is required.

The state directory is mode `0700`; `policy/bundle.json` and `policy/state.json` are atomically written with mode `0600`, protected by a per-state-directory exclusive lock. Raw bundle bytes are persisted unchanged and revalidated before use; their stored digest must still match. A missing, malformed, expired, audience-mismatched, replayed, or unsupported bundle denies; there is no older-bundle or built-in allow fallback. The runtime does not load legacy envelopes or key files.

The rollback/replay watermark (`highest_bundle_version` in `policy/state.json`) is scoped to the bundle audience: installation ID, org ID, and workspace ID together. For the same audience, a candidate with a version lower than or equal to the watermark is rejected as a rollback or replay. When a machine switches installations (for example, `kei setup` with a new runtime token), the first valid candidate for the new audience is treated as a new installation: the previous installation's `state.json` and `bundle.json` are renamed into `policy/archive/<UTC timestamp>-<old installation_id>/` (never deleted), and the new bundle is accepted with its own watermark. A candidate that fails validation leaves the previous installation's state in place.

The `runtime bootstrap`, `runtime heartbeat`, and `serve` startup paths fetch and activate bundles. One-shot `authorize` reads only persisted state. Periodic refresh scheduling is intentionally deferred to HAI-290/T51. A failed candidate never replaces the active bundle; a valid active bundle may be enforced until its `not_after`. 401/403 responses revoke the installation, remove the active bundle, and deny. One-shot `authorize` resolves the human subject online (`POST /api/v1/runtime/subject-attributes:resolve` at `KEI_RUNTIME_CONTROL_PLANE_URL`) when the tool is bound to a connector capability or a policy reached for the call matches on subject attributes (any `src_pattern` other than `*` or `agent:`). A tool service alone does not require subject resolution. Any other tool, such as `web_search` under a `*` or `agent:` policy, is decided from the bundle with no subject and no subject-resolution request. When resolution is needed, unavailable or invalid subject data denies with `subject_resolution_unavailable` before any policy is evaluated.

## Validation and evaluation

Before activation, the runtime checks the canonical schema, duplicate JSON keys, issuer, installation/org/workspace audience, policy revision, strictly increasing bundle version, issued-at time, hard expiry, validity-window limits, and supported policy match semantics. Invalid candidates do not displace an already active bundle.

The runtime checks the tool and its canonical action from the verified policy bundle, not a caller-selected action. Service and connector capability metadata are also read from that bundle. A legacy `action=read, resource=web_search` request does not match the typed tool selector.

Policy matching follows `kei.match/v1`. Today's released `kei-proxy` (`proxy-v0.4.0` is the newest tag) consumes policies in the catalog's array order (ADR-028: `priority DESC`, deny before permit, `id ASC`): the first matching policy decides, and no match denies. Subject memberships are never embedded in the bundle. Approval flags do not act as per-call tokens; workspace access is resolved online. The next section describes the replacement for this ordering, which is merged in the evaluator but not yet released.

A local decision does not move provider payloads, results, or credentials to the catalog. Credential lookup/provider execution remains tenant-side and occurs only after a local allow.

## Deny-overrides evaluation

This section describes behavior that is **not in a released `kei-proxy` yet**. The newest release tag is `proxy-v0.4.0`, and it still orders policies by priority as described above. Deny-overrides ships starting with the `kei-proxy` release that includes it. This page names no version number for it until that tag exists.

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

Under the priority ordering that releases up to `proxy-v0.4.0` use, the first row depends on the two policies' priorities: a permit with a higher priority than the deny would allow the push. That is the difference deny-overrides removes.

### Which bundles carry deny-overrides

A bundle declares it in the policy set:

| Bundle | Where it is declared | Today's validators |
|---|---|---|
| `kei.policy-bundle/v1` | `policy_set.evaluation.order` is `deny_overrides` (the older value is `array_order_first_match`) | The runtime on `main` accepts only `array_order_first_match` here and rejects the rest as unsupported. |
| `kei.policy-bundle/v2` | `deny_overrides` is an entry of `policy_set.evaluation.precedence` | The vendored `policy-set-v2.schema.json` on `main` pins `precedence` to `priority_desc`, `deny_before_permit`, `policy_id_asc`, so a bundle that declares `deny_overrides` fails validation. |

The evaluator in `kei-connector-contracts` already understands both declarations. The runtime's own validators and vendored schemas have not been widened to accept them, and no `kei-proxy` release does either. Until a release does, a runtime must not be sent such a bundle.

The catalog protects older runtimes with a version gate: it leaves a new bundle field out unless the installation's last heartbeated `kei-proxy` version is at least the first release that accepts it, and an installation that has not reported a version gets the oldest shape. The deny-overrides gate is in review in the catalog and uses a placeholder minimum version; it will be set to the release that ships the schema change.

## A bundle the runtime cannot parse

The v1 and v2 bundle schemas are closed: an unknown field, or a value outside a pinned set, is a validation failure, not something the runtime skips. A bundle that fails validation is never activated and never replaces the active bundle, which keeps being enforced until its `not_after`. With no active bundle, every call denies.

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

Support for the field is merged in `kei-proxy` source but is **not in a released `kei-proxy`**: `proxy-v0.4.0` predates it and rejects a bundle that carries it. The catalog emits the field only behind a fleet switch that is off by default and a minimum-version gate; the version in that gate is a placeholder until the release that ships the support is cut. Do not enable the switch before that release is running on the installations that fetch bundles.
