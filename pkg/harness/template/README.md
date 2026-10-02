# Forking a harness adapter

Copy this directory to a sibling package named for the new harness kind. Keep
the `harness.Adapter` implementation as the starting point, then:

1. Replace `Kind` with the canonical harness kind and register it in
   `pkg/harness.ForKind`.
2. Discover built-ins, installed skills, and configured MCP servers by reading
   config and skill files only. Never launch a harness, MCP server, or tool.
   Keep built-ins in `pkg/harness/builtins/<kind>.json`; update its
   `harness_version` and `verified_at` whenever the catalog is checked against
   that harness release.
3. Use the normalized `harness.Tool` names described in ADR-029 §9.3. Discovery
   registers metadata only; it grants no capability or authorization.
4. Render native policy config in `RenderPolicy`. Preserve unmanaged config,
   manage Kei entries explicitly, and make expired bundle entries removable so
   the harness's native ask behavior returns.
5. Implement `Hook` as a report-only decoder. Native harness config decides;
   the hook records the observed decision and never evaluates a policy.
6. Replace `testdata/discovery.golden.json` and add fixture config files copied
   from a real harness configuration with home paths scrubbed. Compare discovery
   output against the golden file.

Bash must remain restricted by default. Model narrowly scoped shell policies
with the `shell:` selector; never add a wholesale Bash allow. Add native config
fixtures and render goldens before enabling the kind in the runtime.
