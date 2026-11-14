# Runtime sessions

A runtime session is the runtime-held identity context for a request. The request names a session by its opaque ID; it does not supply a subject. The runtime resolves the subject when it creates the session, and the local PDP uses that stored subject for policy evaluation (`pkg/pdp/pdp.go:33-44,84-110,174-206`). A linked session's groups for policy matching come from the verified policy bundle, not from caller input or the session's recorded group list (`pkg/pdp/session.go:27-35`).

For tokenless desktop owner calls, when that mode is enabled and the verified owner subject is available, the runtime creates a pinned named session from the installation-owner subject in the active bundle (`runtime/socket_authorize.go:224-286`). An unauthenticated owner-route request without `X-Kei-Session` is bound to that named owner session before authorization (`runtime/socket_authorize.go:667-704`).

Authorization takes one live-session subject snapshot and uses it for both
policy evaluation and audit attribution. A session ended before that snapshot
is denied as `session_not_found`; an end after the snapshot cannot erase the
subject from the in-flight decision or make it appear `subject_unlinked`.


## Create and lifetime

Use `PUT /v1/session` with a `kei.session/v2` request to create a named session. The runtime resolves the subject from the requested identity source and returns the new session ID; callers send it as `X-Kei-Session` on later requests (`runtime/socket_authorize.go:806-890`). The removed `kei.session/v1` schema is rejected with `invalid_request`. In code, `Sessions.Create` makes an opaque `ks_` ID and an independent session (`pkg/pdp/session.go:182-206`). The daemon-owned installation-owner session uses `CreatePinned` (`runtime/socket_authorize.go:264-275`).

Regular named sessions expire after the configured idle TTL (30 minutes by default) and are recycled after the eight-hour maximum age (`pkg/pdp/session.go:63-65,96-97,236-264`). A session can also end through an explicit `DELETE /v1/session`, revocation, or daemon exit (`pkg/pdp/session.go:266-289,339-369`; `runtime/socket_authorize.go:745-760`). The pinned owner session does not expire from idleness; owner-session reconciliation ends and recreates it from the currently verified bundle subject (`runtime/socket_authorize.go:237-286`).

Session failures are distinct:

- `session_not_found` means an ID was never created, has ended, or expired from idleness (`pkg/pdp/session.go:55-57,300-316`).
- `session_revalidation_required` is returned when a named session reaches its maximum age and is recycled; the caller must create a fresh session (`pkg/pdp/session.go:59-65,240-249,293-316`).
- `session_required` means the authorization path requires a named session and the request supplied no session ID. For example, v2 registered harness-tool authorization refuses the empty session ID (`pkg/pdp/pdp.go:240-261`). The unregistered-v2-tool authorization added in runtime PR #241 has the same named-session requirement (`pkg/pdp/pdp.go:253-274` in that PR).

## Requests without a session

A request that names no session carries the empty session ID. The runtime never stores it or treats it as live, and it has no credential store. `PUT /v1/session` rejects the legacy `kei.session/v1` schema with `invalid_request`. `GET /v1/session` and `DELETE /v1/session` without `X-Kei-Session` both return `404 session_not_found`; neither operation reads or changes the empty session ID. The tokenless owner-session rewrite can still bind a headerless owner socket request to its verified named owner session before authorization (`runtime/socket_authorize.go:667-704`).

Runtime audit events always include `session_id`; calls without a session record an empty string, while named and rewritten owner calls record the selected session ID.

## What callers should do

Create a named session with `PUT /v1/session` and `kei.session/v2`, then send the returned `session_id` as `X-Kei-Session` on governed calls. If the runtime returns `session_not_found` or `session_revalidation_required`, create a fresh named session. A request without a session header has no session unless the tokenless owner-session rewrite applies.
