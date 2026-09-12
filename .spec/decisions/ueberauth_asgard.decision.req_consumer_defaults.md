---
id: ueberauth_asgard.decision.req_consumer_defaults
status: accepted
date: 2026-09-12
---

# Request-local transport bounds under consumer defaults

Asgard requires Req `~> 0.7.4`. The prior `~> 0.5.0` constraint excluded the
patched release for [GHSA-655f-mp8p-96gv](https://github.com/wojtekmach/req/security/advisories/GHSA-655f-mp8p-96gv).
The existing Finch 0.22.0 and other lock entries remain compatible and unchanged.

A consumer can set `Req.default_options(finch: [name: Atlas.Finch])`. Req merges
those defaults before building each request. Combining a named Finch pool with
Asgard's former top-level `connect_options` raises before HTTP, which the safe
error handling converted into failed token and JWKS requests.

Asgard now supplies one explicit `finch` option containing `pool_timeout` and
`conn_opts: [transport_opts: [timeout: ...]]`. Req uses or starts a pool for
those options. This replaces the inherited Finch option on this request only;
it does not alter consumer defaults, supervision or the named pool. The existing
connection, pool checkout and receive clamps remain finite at ten seconds or a
shorter positive configured duration. No global timeout or authentication policy
changes are made.

Asgard also explicitly disables response decompression and automatic body
interpretation. Provider endpoints return uncompressed JSON. Host defaults
cannot opt token or JWKS responses into decompression. The regression fixtures
use less than 512 compressed bytes each; they do not construct large payloads.

Actual HTTP tests reproduce the named-pool failure before correction and prove
token exchange, uncached JWKS and full callback success afterward. Existing
PKCE, Basic/form encoding, legacy callback, nonce/signature/claim refusal,
secret redaction and finite timeout controls remain active. Independent
correction review and consumer integration are required for release; prior
reviews of the superseded library candidate do not accept this correction.
