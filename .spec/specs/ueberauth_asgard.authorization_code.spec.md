# Authorization code login

Subject: `ueberauth_asgard.authorization_code`

This library has no Ancora dependency. These requirements are verified by
`test/authorization_code_test.exs` through the library and real Ueberauth pipeline.

1. A code login retains random state, nonce and PKCE verifier in the fetched
   Plug session. The authorization URL carries the S256 challenge, state, nonce
   and requested scopes, including offline_access, but no verifier or secret.
2. A code callback requires matching state no older than ten minutes and
   consumes the pending login. Missing, mismatched or future state fails.
3. Code exchange sends the verifier and exact callback URI. Configured Basic
   authentication removes client credentials from the form body. HTTP requests
   have finite connection and receive timeouts.
4. Only an RS256 token with valid signature, issuer, audience, expiry and
   matching nonce supplies the signed-in user. Code login rejects an implicit
   ID-token callback. Explicit legacy ID-token consumers remain supported.
5. Ueberauth credentials retain the access token, refresh token, expiry and
   granted scopes. The application owns encrypted storage, rotation and OBO.
6. Inspecting the client and logging a failed exchange must not expose client
   secrets, tokens or the PKCE verifier. Remote error descriptions must not be
   copied into callback errors. Request-specific credentials are cleared from
   the connection's private assignments after callback handling.

The pending login is per browser session. A second login replaces the first.
Authorization codes remain single-use at the issuer. The library does not
claim server-side invalidation of a copied, signed browser session cookie.
