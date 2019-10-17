defmodule Ueberauth.Strategy.Asgard.OpenID do
  alias Ueberauth.Strategy.Asgard
  require Logger

  @default_opts [
    response_mode: "query",
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

    query_params = [
      client_id: Keyword.get(opts, :client_id),
      scope: Keyword.get(opts, :scopes),
      response_mode: Keyword.get(opts, :response_mode),
      response_type: Keyword.get(opts, :response_type),
      redirect_uri: Keyword.get(opts, :redirect_uri),
      nonce: generate_nonce(length: 16)
    ]

    query_params =
      if not is_nil(email_hint) do
        Keyword.merge(
          query_params,
          email_hint: email_hint,
          eh_sig: Asgard.Client.generate_email_hint_signature(email_hint, opts)
        )
      else
        query_params
      end

    url <> authorize_endpoint <> "?" <> URI.encode_query(query_params)
  end

  def exchange_code_for_token(opts \\ []) do
    code = Keyword.get(opts, :code)

    client = %Asgard.Client{
      client_id: Keyword.get(opts, :client_id),
      client_secret: Keyword.get(opts, :client_secret),
      redirect_uri: Keyword.get(opts, :redirect_uri)
    }

    with {:token, {:ok, client}} <- {:token, Asgard.Client.get_token(client, code)},
         {:access_token, token} when not is_nil(token) <-
           {:access_token, Map.from_struct(client) |> Map.get(:access_token)},
         {:verify_token, {:ok, _}} <- {:verify_token, verify_token(client)} do
      {:ok, client}
    else
      {:token, _error} ->
        {:error,
         [
           {:error, "access_token"},
           {:error_message, "There was an error communicating with FSID"}
         ]}

      {:access_token, _} ->
        {:error,
         [{:error, "access_token"}, {:error_message, "Expected token call to return a token"}]}

      {:verify_token, _} ->
        {:error, [{:error, "verify_token"}, {:error_message, "Token could not be verified"}]}
    end
  end

  def logout_url(opts \\ []) do
    config = Keyword.merge(default_options(), opts)

    host = Keyword.get(config, :host)
    session_end_endpoint = Keyword.get(config, :session_end_endpoint, "")

    session_end_endpoint =
      session_end_endpoint
      |> case do
        <<"/" <> _>> -> session_end_endpoint
        _ -> "/" <> session_end_endpoint
      end

    host <> session_end_endpoint
  end

  def verify_token(%Asgard.Client{id_token: token}) when is_nil(token) or token === "",
    do: {:error, "id token is not found"}

  def verify_token(%Asgard.Client{} = client) do
    kid = get_kid_from_token(client.id_token)

    jwk =
      Asgard.JWS.get_jwk_by_kid(kid, fn ->
        Logger.debug(fn -> "Didn't find cert in ETS, storing it" end)

        kid
        |> Asgard.Client.certificates!()
        |> JOSE.JWK.from_map()
      end)

    #  {:nonce_valid, true} <- {:nonce_valid, token_nonce_valid?(token, client)}
    with {:verified, {true, jwt, _}} <-
           {:verified, JOSE.JWS.verify_strict(jwk, ["RS256"], client.id_token)},
         {:jwt, %JOSE.JWT{} = jwt} <- {:jwt, jwt |> Poison.decode!() |> JOSE.JWT.from_map()},
         {:expired, true} <- {:expired, validate({:exp, jwt}, client)},
         {:iss_valid, true} <- {:iss_valid, validate({:iss, jwt}, client)},
         {:aud_valid, true} <- {:aud_valid, validate({:aud, jwt}, client)} do
      decoded_token = decode_token(client.id_token)
      {:ok, decoded_token}
    else
      {:verified, {false, _, _}} -> {:error, "The token provided could not be verified"}
      {:jwt, _} -> {:error, "Error parsing JWT"}
      {:expired, false} -> {:error, "The token is expired"}
      {:iss_valid, false} -> {:error, "The issuer cannot be verified"}
      {:aud_valid, false} -> {:error, "The token's audience cannot be verified"}
      error -> {:error, error}
    end
  end

  def decode_signature(token), do: JOSE.JWT.peek_protected(token)

  @spec decode_token(binary | {any, binary | map} | map) :: [any] | JOSE.JWT.t()
  def decode_token(token), do: JOSE.JWT.peek_payload(token)

  defp default_options(),
    do: Keyword.merge(@default_opts, Application.get_env(:ueberauth, __MODULE__, []))

  defp generate_nonce(length: length),
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

  defp validate({type, %JOSE.JWT{} = jwt}, %Asgard.Client{} = client),
    do: do_validate({type, jwt.fields}, client)

  defp do_validate({:exp, token}, _client), do: :os.system_time(:seconds) < token["exp"]

  defp do_validate({:iss, token}, _client) do
    host = Application.get_env(:ueberauth, Ueberauth.Strategy.Asgard.OpenID) |> Keyword.get(:host)
    host === token["iss"]
  end

  defp do_validate({:aud, token}, client), do: client.client_id === token["aud"]
end
