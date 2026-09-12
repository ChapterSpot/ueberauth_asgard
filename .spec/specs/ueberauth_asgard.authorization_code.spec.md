# Authorization code login

Subject: `ueberauth_asgard.authorization_code`

This library has no Ancora dependency. These requirements are verified by
`test/authorization_code_test.exs` through the library and real Ueberauth pipeline,
and `test/client_test.exs` through Req against a local HTTP server.

1. A code login retains random state, nonce and PKCE verifier in the fetched
   Plug session. The authorization URL carries the S256 challenge, state, nonce
   and requested scopes, including offline_access, but no verifier or secret.
2. A code callback requires matching state no older than ten minutes and
   consumes the pending login. Missing, mismatched or future state fails.
3. Code exchange sends the verifier and exact callback URI. Configured Basic
   authentication removes client credentials from the form body. HTTP requests
   use Req with automatic retries and redirects disabled, so single-use codes
   are never replayed by the transport. Connection, pool checkout and receive
   timeouts default to 10 seconds. Optional `connect_timeout` and
   `receive_timeout` settings can shorten these bounds but cannot remove or
   extend them. Request-local Finch connection and pool options must override
   inherited named-Finch defaults without changing global Req configuration or
   reconfiguring the host pool.
4. Only an RS256 token with valid signature, issuer, audience, expiry and
   matching nonce supplies the signed-in user. Code login rejects an implicit
   ID-token callback. Explicit legacy ID-token consumers remain supported.
5. Ueberauth credentials retain the access token, refresh token, expiry and
   granted scopes. The application owns encrypted storage, rotation and OBO.
6. Inspecting the client and logging a failed exchange must not expose client
   secrets, tokens or the PKCE verifier. Remote error descriptions must not be
   copied into callback errors. Only recognized OAuth error codes are retained;
   arbitrary provider error values, malformed JSON, invalid token fields,
   non-success responses and transport failures return bounded neutral errors.
   Request-specific credentials are cleared from
   the connection's private assignments after callback handling.

7. Certificate requests use the same bounded Req transport. Only successful
   responses with a JWKS list of objects are accepted; malformed and non-2xx
   responses return safe errors. Bang lookups raise fixed messages without
   inspecting response bodies or request data. The complete code callback test
   obtains an uncached RSA key over local HTTP before RS256 verification.
8. The dependency and runtime application graph contains neither HTTPoison nor
   Hackney. Req is constrained to `~> 0.7.4`, excluding releases affected by
   GHSA-655f-mp8p-96gv. The supported Elixir minimum remains 1.15.
9. Token and JWKS responses must not trigger automatic decompression or archive
   decoding, even when the host opts into compression globally. Small gzip and
   layered-gzip fixtures return neutral errors without exposing their contents.

The pending login is per browser session. A second login replaces the first.
Authorization codes remain single-use at the issuer. The library does not
claim server-side invalidation of a copied, signed browser session cookie.

Transport witnesses cover Basic credential escaping, exact form fields and
PKCE verifier, legacy client-secret POST, refresh-credential retention and scope
fallback, 503 without retry, redirect refusal, malformed JSON and JWKS, remote
error sanitization, refused connection and a delayed response receive timeout.
Token exchange, uncached JWKS lookup, the complete callback and the delayed
receive-timeout witness also run with an actual supervised `Atlas.Finch` and
`Req.default_options(finch: [name: Atlas.Finch])`. The host defaults and pool
remain usable after Asgard requests; tests restore global settings and supervised
state. Explicit legacy ID-token callback success remains covered. Refresh requests and
rotation remain application-owned, as before this transport change.
