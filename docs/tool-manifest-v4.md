# Tool manifest v4

V4 is the strict tool-registration format for typed connector tools with
policy-evaluable operation plans. The runtime accepts it during
`kei-proxy runtime bootstrap` (through `KEI_TOOL_MANIFEST`) and through the
authenticated socket endpoint `POST /v1/tools:register`.

## Connector tools

A `connector_binding` entry must include the registered agent and connector
IDs, non-empty `required_capabilities`, and a plan. The runtime validates the
plan with the same closed plan validator used by v2 bundle authorization. The
plan declares closed object schemas for model arguments and hidden context,
then maps them to a bounded set of operations. Each operation must use a
registered capability and declared resource type, and its provider input must
be a JSON object template. Invalid or incomplete plans are rejected before
registration is sent to the catalog.

The plan is metadata, not a grant. The catalog still checks that the agent is
assigned to the runtime installation and bound to the connector. Policy must
still explicitly allow the requested tool/capability/resource. Runtime
authorization validates call arguments against the plan in the active bundle;
the runtime does not execute the provider call.

## Harness-executor tools

A `harness_executor` entry may omit the plan and connector-only fields. The
route must identify its executor and registration. Other v4 tool metadata
follows the catalog's v4 contract.

## Merge behavior and negotiation

V4 sync may omit `sync_mode` or set it to `replace` (the default) or `merge`.
Merge updates only the listed installation-owned tools and retains omitted
ones. V3 continues to replace the installation-owned set and rejects
`sync_mode`.

The runtime sends `application/vnd.kei.tool-manifest.v4+json` in `Accept` and
requires the catalog to acknowledge v4 in both
`X-Kei-Tool-Manifest-Schema` and `X-Kei-Supported-Tool-Manifest-Schemas`.
Missing or mismatched negotiation fails closed before the sync is considered
successful. See [protocol negotiation](contracts/tool-manifest-negotiation.md)
and the catalog's [v4 sync contract](https://github.com/HaikeiLabs/kei-policy-catalog/blob/main/docs/tool-manifest-v4.md).
