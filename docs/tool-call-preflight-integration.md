# Runtime tool-call preflight integration gate

**Status: incomplete; fail closed until HAI-392 and HAI-280 integrations land.**

The runtime's local authorization socket exposes internal `POST /v1/preflight` and `POST /v1/consume` requests (`kei.tool-preflight-request/v1`, `kei.operation-consume-request/v1`). The caller supplies tool invocation arguments and, on consume, the opaque handle plus the exact operation it is attempting. It does not supply the route, planner, capability list, or agent identity. All routes require the runtime bearer token.

The trusted registration seam is `LocalPDP.RegisterOperationPlanner`: HAI-392 must provide the registered typed route, assignment-resolved agent ID, an argument validator, and an operation planner. The planner receives validated arguments and trusted binding context. It must enumerate the complete exact connector operation plan before any provider request; response-dependent targets must be split into separate calls. Missing planner, invalid/incomplete plan, nonmatching capability/resource type, or any denied operation rejects the whole preflight.

The route shape is a one-of object with `connector_binding` or `harness_executor`. Connector tool registrations require non-empty `required_capabilities` and `resource_types`; harness executor routes omit those connector-only fields. Runtime execution authorizes connector plans only. Connector binding is authoritative when present; no independent execution-class flag is used.

Successful preflight stores the approved plan in process memory and returns an opaque random handle with a bounded 15-second expiry. The store binds installation, active bundle digest, session subject, trusted registered agent, tool, typed route, delegation context, and exact plan entries. Each entry can be consumed once. Expiry, replay, changed target/context, bundle refresh, or runtime restart invalidates authorization. Handles and plans must not be logged. Connector invocation consumes an entry before its existing catalog/provider path; catalog authorization remains in place.

## Integration gates

1. HAI-392's typed v3 manifest/route types are proposed in open PR #130. This branch deliberately does not duplicate `runtime/tool_manifest.go`. Runtime startup still does not register trusted typed routes, assigned agents, validated-args validators, and operation planners with the local PDP; until that integration exists, preflight returns `planner_unavailable`.
2. HAI-280's policy-set v2 structured checks are not supported by the current runtime evaluator. Do not invent a conversion to legacy resource strings: typed resource type/id/parent decisions must use the locally cached verified policy bundle, with no control-plane calls during preflight/consume. Unsupported bundle schemas remain fail-closed.
3. End-to-end tests must connect an actual registered tool's complete plan to connector invocation and prove provider non-invocation before permit, any-operation denial, exact one-use consumption, replay/substitution denial, and v1 compatibility. Keep PR #129 marked incomplete until all gates pass.
