# Runtime tool-manifest protocol negotiation

`PUT /api/v1/runtime/tools` uses explicit negotiation headers in addition to
the schema-tagged JSON body. Runtime bootstrap and the authenticated local
socket route `POST /v1/tools:register` share the same parser and catalog sync
client. The socket route returns the catalog's `added`, `updated`, `removed`,
and `unchanged` counts; it uses the runtime installation credential and never
reads or writes a manifest file.

The runtime accepts v3 and v4 manifests. V1, v2, schema-less, and unknown
versions are rejected before a catalog request. V3 retains its existing
replace behavior and must omit v4-only fields. V4 is strictly decoded; connector
routes must include a valid bounded operation plan, and harness-executor routes
must omit connector-only fields and plans. The runtime validates plans using
the same closed plan profile used for v2 policy-bundle decisions. Registration
is metadata only and does not grant policy access.

- Request `Accept` includes `application/json` for the sync-count response and
  exactly one versioned protocol media type: either
  `application/vnd.kei.tool-manifest.v3+json` or
  `application/vnd.kei.tool-manifest.v4+json`.
- The request media type and JSON `schema` must match. A mismatch is rejected
  before writes. Unknown proposals receive HTTP 406 with supported versions.
- The catalog returns `X-Kei-Supported-Tool-Manifest-Schemas` listing the
  versions it supports and, after successful sync, echoes the selected schema
  in `X-Kei-Tool-Manifest-Schema`. The response body remains `application/json`
  with sync counts. Runtime requires both the matching echo and supported
  version advertisement; missing or mismatched negotiation fails closed.
- V4 may omit `sync_mode` or select `replace` (the default) or `merge`. V3
  always replaces the installation-owned set and rejects `sync_mode`.

Negotiation happens only at bootstrap or explicit tool registration, never per
tool decision. Unsupported or invalid manifests never mutate the catalog's
installation tool set. A non-2xx bootstrap sync is logged and remains
non-fatal to runtime startup; for a catalog 400, the surfaced error includes
the catalog message (or a trimmed body capped at 500 bytes).
