# Runtime policy bundles

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

The `runtime bootstrap`, `runtime heartbeat`, and `serve` startup paths fetch and activate bundles. One-shot `authorize` reads only persisted state. Periodic refresh scheduling is intentionally deferred to HAI-290/T51. A failed candidate never replaces the active bundle; a valid active bundle may be enforced until its `not_after`. 401/403 responses revoke the installation, remove the active bundle, and deny. A human subject is resolved online for every one-shot authorization; unavailable or invalid subject data denies before any policy is evaluated.

## Validation and evaluation

Before activation, the runtime checks the canonical schema, duplicate JSON keys, issuer, installation/org/workspace audience, policy revision, strictly increasing bundle version, issued-at time, hard expiry, validity-window limits, and supported policy match semantics. Invalid candidates do not displace an already active bundle.

The runtime checks the tool registry and uses the registered action from the bundle, not a caller-selected action. The exact default tool mappings are `web_search` → `tool:web_search` and `search_wiki` → `tool:search_wiki`. They are covered by unsigned bundle tests; the canonical fixture remains byte-for-byte unchanged. A legacy `action=read, resource=web_search` request does not match either typed tool selector.

Policy matching follows `kei.match/v1`; policies are consumed in the catalog's array order (ADR-028: `priority DESC`, deny before permit, `id ASC`). The first matching policy decides, and no match denies. Subject memberships are never embedded in the bundle. Approval flags do not act as per-call tokens; workspace access is resolved online.

A local decision does not move provider payloads, results, or credentials to the catalog. Credential lookup/provider execution remains tenant-side and occurs only after a local allow.
