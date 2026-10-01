# Runtime policy bundles

`kei-proxy` enforces signed `kei.policy-bundle/v1` bundles locally. The
canonical schemas live in Kei's `docs/contracts/`; this repository vendors the
schema and fixture files without changing them. The runtime test also pins the
fixture hashes from `fixtures/kei/README.md`.

## Bootstrap and state

Set `KEI_RUNTIME_TOKEN`, `KEI_RUNTIME_CONTROL_PLANE_URL`, and a writable
`KEI_RUNTIME_STATE_DIR` (default `/var/lib/kei-proxy`). The runtime obtains the
signing key set only from the authenticated control-plane key endpoint, pins
revocations monotonically, then fetches and verifies the current DSSE envelope.
No key from a bundle, environment variable, or operator-provided file is trusted.
`kei-pb-000000-*` public example keys are accepted only by tests, never in
production/staging.

The state directory is mode `0700`; `policy/envelope.json`, `policy/keys.json`,
and `policy/state.json` are atomically written with mode `0600`, protected by a
per-state-directory exclusive lock. A persisted envelope is reverified before
use. An absent, malformed, expired, audience-mismatched, replayed, revoked, or
unsupported bundle denies; there is no older-bundle or built-in allow fallback.

The `runtime bootstrap`, `runtime heartbeat`, and `serve` startup paths fetch and
activate bundles. One-shot `authorize` reads only persisted state. Periodic
refresh scheduling is intentionally deferred to T51. A failed candidate never replaces the active bundle; a valid active bundle may
be enforced until its signed `not_after`. 401/403 revocation responses delete
the active envelope and deny. A human subject is
resolved online for every one-shot authorization; unavailable or invalid
subject data denies before any policy is evaluated.

## Evaluation

The runtime checks the tool registry and uses the registered action from the
bundle, not a caller-selected action. The user-directed default tool mappings
are `web_search` → `tool:web_search` and `search_wiki` → `tool:search_wiki`.
They are covered by T49-specific tests; the canonical fixture remains
byte-for-byte unchanged until its owner versions a replacement. In particular,
a legacy `action=read, resource=web_search` request does not match either typed
tool selector.

Policy matching follows `kei.match/v1`; policies are consumed in the catalog's
array order (ADR-028: `priority DESC`, deny before permit, `id ASC`). The first
matching policy decides, and no match denies. Subject memberships are never
embedded in the bundle. Approval flags do not act as per-call tokens; workspace
access is resolved online.

A local decision does not move provider payloads, results, or credentials to the
catalog. Credential lookup/provider execution remains tenant-side and occurs
only after a local allow.
