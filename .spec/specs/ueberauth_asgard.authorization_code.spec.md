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
   extend them.
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
   Hackney. The supported Elixir minimum is 1.15 for the resolved Req/Finch stack.

The pending login is per browser session. A second login replaces the first.
Authorization codes remain single-use at the issuer. The library does not
claim server-side invalidation of a copied, signed browser session cookie.

Transport witnesses cover Basic credential escaping, exact form fields and
PKCE verifier, legacy client-secret POST, refresh-credential retention and scope
fallback, 503 without retry, redirect refusal, malformed JSON and JWKS, remote
error sanitization, refused connection and a delayed response receive timeout.
Explicit legacy ID-token callback success remains covered. Refresh requests and
rotation remain application-owned, as before this transport change.
