defmodule Ueberauth.Strategy.Asgard.OpenID do
  import UeberauthAsgard.Strategy.Asgard.JWS, only: [get_jwk_by_kid: 2]

  @default_opts [
    response_type: "id_token",
    scopes: "openid email"
  ]

  def authorize_url!(opts \\ []) do
    opts = Keyword.merge(@default_opts, opts)

    opts
  end

  def verify_token(token) when is_nil(token) or token === "", do: {:error, "id token is not found"}

  def verify_token(token) do
    kid = get_kid_from_token(token)

    # 1. Is signature valid
    get_jwk_by_kid(kid, fn ->
      load_certificates()
    end)
    |> JOSE.JWS.verify_strict(["RS256"], token)

    # 2. Is the token expired?

    # 3. Does the token iss match the configured host

    # 4. Does the aud match the client_id

    decoded_token = %{}
    {:ok, decoded_token}
  end

  def decode_token(token) do
    JOSE.JWT.peek_payload(token)
  end

  def decode_signature(token) do
    JOSE.JWT.peek_protected(token)
  end

  def get_kid_from_token(token) do
    %JOSE.JWS{
      fields: %{
        "kid" => kid,
        "typ" => "JWT"
      }
    } = decode_signature(token)

    kid
  end

  def load_certificates(opts \\ []) do
    %HTTPoison.Response{body: keys} = HTTPoison.get!("https://asgard.dev.c-spot.run/certificates")

    JOSE.JWK.from(keys)
  end

end
