defmodule Ueberauth.Strategy.Asgard.OpenID do
  alias Ueberauth.Strategy.Asgard
  require Logger

  @default_opts [
    response_type: "code",
    scopes: "openid email profile",
    host: "https://asgard.dev.c-spot.run",
    internal_host: "http://asgard:3000",
    authorize_endpoint: "/authorize",
    token_endpoint: "/token",
    certificates_endpoint: "/certificates",
    session_end_endpoint: "/session/end"
  ]

  def authorize_url!(opts \\ []) do
    opts = Keyword.merge(default_options(), opts)
    url = Keyword.get(opts, :host)
    authorize_endpoint = Keyword.get(opts, :authorize_endpoint)
    email_hint = Keyword.get(opts, :email_hint)

    Logger.debug("Ueberauth.Strategy.Asgard.OpenID opts: #{inspect(opts)}")

    query_params =
      [
        client_id: Keyword.get(opts, :client_id),
        scope: Keyword.get(opts, :scopes),
        response_type: Keyword.get(opts, :response_type),
        redirect_uri: Keyword.get(opts, :redirect_uri),
        nonce: generate_nonce(length: 16),
      ]

    query_params =
      if not is_nil(email_hint) do
        Keyword.merge(
          query_params,
          [email_hint: email_hint, eh_sig: Asgard.Client.generate_email_hint_signature(email_hint, opts)]
        )
      else
        query_params
      end

    url <> authorize_endpoint <> "?" <> URI.encode_query(query_params)
  end

  def exchange_code_for_token(opts \\ []) do
    code = Keyword.get(opts, :code)

    client =
      %Asgard.Client{
        client_id: Keyword.get(opts, :client_id),
        client_secret: Keyword.get(opts, :client_secret),
        redirect_uri: Keyword.get(opts, :redirect_uri)
      }

    # TODO: We should technically verify this token, or call /userinfo endpoint
    # to get the user details, but for the sake of time, this will suffice for now. (JB)

    # TODO: No nested cases! Rewrite as a with statement
    case client |> Asgard.Client.get_token(code) do
      {:ok, %Asgard.Client{access_token: nil}} ->
        {:error, [{:error, "no_access_token"}, {:error_message, "Expected token call to return a token"}]}

      {:ok, client} ->
        case verify_token(client.id_token) do
          {:ok, _} -> {:ok, client}
          {:error, error} -> {:error, [{:error, "invalid_token"}, {:error_message, error}]}
        end

      {:error, error} ->
        {:error, error}
    end
  end

  def logout_url(opts \\ []) do
    config = Keyword.merge(default_options(), opts)

    host = Keyword.get(config, :host)
    session_end_endpoint = Keyword.get(config, :session_end_endpoint, "")

    session_end_endpoint =
      session_end_endpoint |> case do
        <<"/" <> _>> -> session_end_endpoint
        _ -> "/" <> session_end_endpoint
      end

    host <> session_end_endpoint
  end

  def verify_token(token) when is_nil(token) or token === "",
    do: {:error, "id token is not found"}

  # TODO (JB)
  def verify_token(token) do
    kid = get_kid_from_token(token)

    # 1. Is signature valid
    Asgard.JWS.get_jwk_by_kid(kid, fn ->
      Logger.debug("Didn't find cert in ETS, storing it")
      Asgard.Client.certificates!(kid)
    end)
    |> JOSE.JWS.verify_strict(["RS256"], token)

    # 2. Is the token expired?

    # 3. Does the token iss match the configured host

    # 4. Does the aud match the client_id

    # 5. Validate nonce?

    decoded_token = decode_token(token)
    {:ok, decoded_token}
  end


  def decode_signature(token), do: JOSE.JWT.peek_protected(token)

  @spec decode_token(binary | {any, binary | map} | map) :: [any] | JOSE.JWT.t()
  def decode_token(token), do: JOSE.JWT.peek_payload(token)

  defp default_options(),
    do: Keyword.merge(@default_opts, Application.get_env(:ueberauth, __MODULE__, []))

  defp generate_nonce([length: length]),
    do: :crypto.strong_rand_bytes(length) |> Base.url_encode64(padding: false)

  defp get_kid_from_token(token) do
    %JOSE.JWS{
      fields: %{
        "kid" => kid,
        "typ" => "JWT"
      }
    } = decode_signature(token)

    kid
  end

  defp validate({:exp, token}), do: :os.system_time(:seconds) < token.exp
  defp validate({:iss, token}),
    do: Application.get_env(:ueberauth_asgard, Ueberauth.Strategy.Asgard.OpenID, :host) === token.iss
  defp validate({:aud, token}),
    do: Application.get_env(:ueberauth_asgard, Ueberauth.Strategy.Asgard.OpenID, :client_id) === token.aud
end
