# Tool manifest v3 routes

A v3 connector route carries both explicit `agent_id` and `connector_id`, plus non-empty `required_capabilities`. Runtime validates this closed route shape but does not infer either identity from caller/default-agent metadata. The catalog is authoritative for confirming installation assignment and the exact workspace/agent/connector binding and capability subset during sync.

Harness-native routes use `harness_executor` and omit connector-only capabilities and resource types. V3 remains supported and must be explicitly negotiated; a missing, mismatched, unsupported, or unacknowledged protocol fails closed before sync. Runtime also supports v4, which adds validated connector operation plans and merge sync; see [Tool manifest v4](tool-manifest-v4.md). The shared v3 wire example is `fixtures/kei/tool-manifest.v3.json` in Agentware.
