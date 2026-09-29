# Runtime token canonicalization notes

## Shared wiki search

On 2026-09-24, these searches each returned no results:

- `wiki search "tenant data distributed proxy" --top-k 10`
- `wiki search "HAI-119 runtime token" --top-k 10`
- `wiki search "connector runtime token" --top-k 10`

## Decision applied

Per ADR-020 / HAI-119, `KEI_RUNTIME_TOKEN` is the sole runtime installation
credential input. The legacy harness-token name is removed; runtime credentials must not
be accepted through `--key` or `--harness-key` aliases. Protocol fields named
`harness_token` remain unchanged where they are control-plane contracts.

`init --key` is an ABAC service secret and is unrelated to runtime token
authentication.
