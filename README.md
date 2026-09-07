# Ueberauth Asgard

OIDC login through Asgard for Phoenix and Plug applications.

## Authorization code login

Fetch the Plug session before invoking Ueberauth. Configure the provider with
its existing confidential client ID and secret:

```elixir
config :ueberauth, Ueberauth,
  providers: [
    asgard: {Ueberauth.Strategy.Asgard,
      client_id: System.fetch_env!("ASGARD_CLIENT_ID"),
      client_secret: System.fetch_env!("ASGARD_CLIENT_SECRET"),
      callback_methods: ["GET"],
      response_type: "code",
      scopes: "openid profile email offline_access",
      token_endpoint_auth_method: "client_secret_basic"}
  ]

config :ueberauth, Ueberauth.Strategy.Asgard.OpenID,
  host: "https://asgard.chapterspot.com",
  internal_host: "https://asgard.chapterspot.com",
  response_type: "code",
  response_mode: "query"
```

The strategy creates an S256 PKCE verifier, nonce and state for each login.
It retains them in the Plug session for at most ten minutes and consumes them
on the code callback. Starting another login replaces the pending login in
that browser. The token exchange sends the verifier and exact callback URL.
RS256 signature, issuer, audience, expiry and nonce must verify before the
strategy returns a user. An ID-token-only callback cannot complete a code login.

Verified credentials include `token`, `refresh_token`, `expires_at` as a
`DateTime`, and `scopes`. Applications must store these credentials on the
server. Do not put them in browser cookies, logs, chat context or job arguments.
This library retains the returned refresh token; the application owns refresh
rotation, storage and revocation. It does not perform delegated token exchange.

Asgard requires a registered exact callback, PKCE, the code and refresh grants,
`offline_access`, and first-party status to issue refresh tokens. These are
client settings managed by the FSID administrator.

Existing consumers configured for `response_type: "id_token"` retain that
callback path. New consumers should use code login. Client-secret POST remains
the default token authentication method for compatibility; select Basic as shown
above for the new Asgard configuration.

## Verification

`mix test` exercises the complete Ueberauth request/callback, PKCE verifier and
Basic authentication on the token request, refresh-credential retention,
state expiry, claim and signature rejection, and secret-free log output.
The behavioral contract is in
[the authorization-code spec](.spec/specs/ueberauth_asgard.authorization_code.spec.md).

Local verification for this change ran in a Docker container with Elixir 1.19
and OTP 28. Run formatting, tests and `mix compile --warnings-as-errors` in the
consumer's supported Elixir environment before updating its dependency pin.
