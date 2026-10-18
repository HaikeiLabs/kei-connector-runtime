# Runtime tool-manifest protocol negotiation

`PUT /api/v1/runtime/tools` uses explicit negotiation headers in addition to
its schema-tagged JSON body:

Clients that do not bootstrap through Agentware may send that same manifest
body to `POST /v1/tools:register` on the authenticated local runtime socket.
The runtime validates the manifest and forwards it through the same catalog
sync client, returning the catalog's `added`, `updated`, `removed`, and
`unchanged` counts. Invalid/empty manifests return `400 invalid_manifest`;
catalog errors return `tool_sync_error` (catalog `400` messages are preserved).
The route uses the runtime installation credential and never reads or writes a
manifest file. It accepts the runtime's supported v2, v3, and v4 manifest
schemas.

- Request `Accept` includes `application/json` for the sync-count response and
  exactly one versioned protocol media type:
  `application/vnd.kei.tool-manifest.v2+json` or
  `application/vnd.kei.tool-manifest.v3+json`.
- The catalog returns `X-Kei-Supported-Tool-Manifest-Schemas` listing the
  versions it supports and, after successful sync, echoes the selected schema
  in `X-Kei-Tool-Manifest-Schema`. The response body remains `application/json`
  with sync counts.
- The request header and JSON `schema` must match. A mismatch is rejected
  before writes. Unknown proposals receive HTTP 406 with supported versions;
  v3 without an explicit proposal receives HTTP 400.
- New runtimes require both the v3 echo and supported-version advertisement
  before considering a v3 sync successful. A missing/mismatched v3 response
  fails closed. V2 may interoperate with an older catalog that does not send
  negotiation headers; new catalogs still negotiate v2 when the runtime
  proposes it.
- The catalog retains a legacy v2-only request mode when the protocol header
  is absent. It does not permit that legacy mode for v3.

Negotiation happens only at bootstrap tool sync, never per tool decision.
Unsupported protocols never mutate the catalog's installation tool set.

A non-2xx sync is non-fatal on the runtime: it is logged and bootstrap
continues. For a 400, the surfaced error additionally carries the catalog's
`message` field (or the trimmed body, capped at 500 bytes) so the caller sees
why the manifest was rejected.
