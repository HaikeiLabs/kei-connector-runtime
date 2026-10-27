# Runtime sessions

A runtime session is the runtime-held identity context for a request. The request names a session by its opaque ID; it does not supply a subject. The runtime resolves the subject when it creates the session, and the local PDP uses that stored subject for policy evaluation (`pkg/pdp/pdp.go:33-44,84-110,174-206`). A linked session's groups for policy matching come from the verified policy bundle, not from caller input or the session's recorded group list (`pkg/pdp/session.go:27-35`).

For tokenless desktop owner calls, when that mode is enabled and the verified owner subject is available, the runtime creates a pinned named session from the installation-owner subject in the active bundle (`runtime/socket_authorize.go:224-286`). An unauthenticated owner-route request without `X-Kei-Session` is bound to that named owner session before authorization (`runtime/socket_authorize.go:667-704`). This owner session is distinct from the legacy default session described below.

## Create and lifetime

Use `PUT /v1/session` with a `kei.session/v2` request to create a named session. The runtime resolves the subject from the requested identity source and returns the new session ID; callers send it as `X-Kei-Session` on later requests (`runtime/socket_authorize.go:806-890`). In code, `Sessions.Create` makes an opaque `ks_` ID and an independent session (`pkg/pdp/session.go:182-206`). The daemon-owned installation-owner session uses `CreatePinned` (`runtime/socket_authorize.go:264-275`).

Regular named sessions expire after the configured idle TTL (30 minutes by default) and are recycled after the eight-hour maximum age (`pkg/pdp/session.go:63-65,96-97,236-264`). A session can also end through an explicit `DELETE /v1/session`, revocation, or daemon exit (`pkg/pdp/session.go:266-289,339-369`; `runtime/socket_authorize.go:745-760`). The pinned owner session does not expire from idleness; owner-session reconciliation ends and recreates it from the currently verified bundle subject (`runtime/socket_authorize.go:237-286`).

Session failures are distinct:

- `session_not_found` means an ID was never created, has ended, or expired from idleness (`pkg/pdp/session.go:55-57,300-316`).
- `session_revalidation_required` is returned when a named session reaches its maximum age and is recycled; the caller must create a fresh session (`pkg/pdp/session.go:59-65,240-249,293-316`).
- `session_required` means the authorization path requires a named session and the request supplied the empty default ID. For example, v2 registered harness-tool authorization refuses the default session (`pkg/pdp/pdp.go:240-261`). The unregistered-v2-tool authorization added in runtime PR #241 has the same named-session requirement (`pkg/pdp/pdp.go:253-274` in that PR).

## Legacy default session

`pdp.DefaultSession` is the empty session ID. It is used when a request names no session. It is implicit and is not bound to a verified identity. The code deprecates it with the notice: “name a session created with Create; the default session goes away after one release” (`pkg/pdp/session.go:50-53`). A legacy `kei.session/v1` `PUT /v1/session` starts or replaces this single default session; the v2 request creates a named session instead (`pkg/pdp/session.go:152-180`; `runtime/socket_authorize.go:806-890`).

The current authorization paths treat the empty ID differently:

| Entry point | Legacy default behavior |
| --- | --- |
| `Evaluator.Evaluate` and `Evaluator.EvaluateConnector` | Accept the empty ID as live. They evaluate using the stored default subject if one exists; a policy may still deny the call (`pkg/pdp/pdp.go:84-110,147-206`). |
| Generic `/v1/authorize` path | The runtime uses `Evaluator.Evaluate` for calls that do not take a specialized v2 path, so the default session remains accepted as the legacy context (`runtime/socket_authorize.go:1127-1175` on main). |
| Connector and command execution | Legacy connector calls use `EvaluateConnector`, which accepts the default if it has an active subject. The commands:run route resolves credential references through `ConnectorGrant`, which also needs a linked subject for the target; `Sessions.Get` can read the active default subject (`runtime/connector_grant.go`; `pkg/pdp/session.go:209-224`). |
| V2 registered harness-tool authorization | Refuses the default with `session_required` (`pkg/pdp/pdp.go:240-261`). |
| V2 MCP and model authorization | Do not require a named ID: both use `sessionLive`, which treats the default ID as live, then evaluate with its stored subject if present (`pkg/pdp/pdp.go:100-110,275-324`). |
| Pi shell authorization | Does not require a named ID, but needs an active subject in `Sessions`; an empty default with no stored subject returns `session_not_found` (`pkg/pdp/pi_shell.go:15-28`; `pkg/pdp/session.go:209-224`). |
| V2 plan/preflight | Removed with the connector invoke path (HAI-724): the runtime no longer plans or consumes operation plans. |
| Tool-bound credential release | Refuses the default with `session_not_found`; this path requires a live named session (`runtime/socket_authorize.go:1180-1186`). |
| MCP route-key creation | Refuses the default with `session_not_found` (`runtime/socket_authorize.go:497-506`). |
| V2 unregistered-tool authorization | `AuthorizeV2UnregisteredTool` returns deny with `session_required` for the default ID. This entry point is in runtime PR #241 and is not present on the fetched main revision (`pkg/pdp/pdp.go:253-263` in PR #241). |

A missing session header on the owner-only socket can be rewritten to the verified owner session before the authorization path runs. That owner-session behavior is not use of `pdp.DefaultSession` (`runtime/socket_authorize.go:667-704`).

## What callers should do

Create a named session with `PUT /v1/session` and `kei.session/v2`, then send the returned `session_id` as `X-Kei-Session` on governed calls. If the runtime returns `session_not_found` or `session_revalidation_required`, create a fresh named session. Do not rely on an omitted session header or the legacy `kei.session/v1` session.

## Deprecation

Removal of the legacy default session is tracked in [Linear HAI-878](https://linear.app/haikeilabs/issue/HAI-878).
