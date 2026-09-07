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

  @spec authorize_url!([]) :: URI.t()
  def authorize_url!(opts \\ []) do
    opts = Keyword.merge(default_options(), opts)
    url = Keyword.get(opts, :host)
    authorize_endpoint = Keyword.get(opts, :authorize_endpoint)
    email_hint = Keyword.get(opts, :email_hint)

    query_params =
      [
        client_id: Keyword.get(opts, :client_id),
        scope: Keyword.get(opts, :scopes),
        response_mode: Keyword.get(opts, :response_mode),
        response_type: Keyword.get(opts, :response_type),
        redirect_uri: Keyword.get(opts, :redirect_uri),
        nonce: Keyword.get_lazy(opts, :nonce, fn -> generate_nonce(length: 32) end),
        code_challenge: Keyword.get(opts, :code_challenge),
        code_challenge_method: Keyword.get(opts, :code_challenge_method),
        state: Keyword.get(opts, :state),
        acr_values: Keyword.get(opts, :acr_values)
      ]
      |> Enum.filter(fn {_k, v} -> not is_nil(v) end)

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
      |> URI.encode_query()

    (url <> authorize_endpoint <> "?")
    |> Kernel.<>(query_params)
    |> URI.parse()
  end

  def exchange_code_for_token(opts \\ []) do
    code = Keyword.get(opts, :code)

    client = %Asgard.Client{
      client_id: Keyword.get(opts, :client_id),
      client_secret: Keyword.get(opts, :client_secret),
      code_verifier: Keyword.get(opts, :code_verifier),
      nonce: Keyword.get(opts, :nonce),
      token_endpoint_auth_method: Keyword.get(opts, :token_endpoint_auth_method),
      redirect_uri: Keyword.get(opts, :redirect_uri)
    }

    with {:token, {:ok, client}} <- {:token, Asgard.Client.get_token(client, code)},
         {:access_token, token} when not is_nil(token) <-
           {:access_token, Map.from_struct(client) |> Map.get(:access_token)},
         {:verify_token, {:ok, _}} <- {:verify_token, verify_token(client)} do
      {:ok, client}
    else
      {:token, _error} ->
        Logger.error("Error communicating with FSID")

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
  rescue
    _ -> {:error, "FSID token exchange failed"}
  catch
    _, _ -> {:error, "FSID token exchange failed"}
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
      Asgard.JWS.get_jwk_by_kid({Keyword.get(default_options(), :host), kid}, fn ->
        Logger.debug(fn -> "Didn't find cert in ETS, storing it" end)

        kid
        |> Asgard.Client.certificates!()
        |> JOSE.JWK.from_map()
      end)

    with {:verified, {true, jwt, _}} <-
           {:verified, JOSE.JWS.verify_strict(jwk, ["RS256"], client.id_token)},
         {:jwt, %JOSE.JWT{} = jwt} <- {:jwt, jwt |> Poison.decode!() |> JOSE.JWT.from_map()},
         {:expired, true} <- {:expired, validate({:exp, jwt}, client)},
         {:iss_valid, true} <- {:iss_valid, validate({:iss, jwt}, client)},
         {:aud_valid, true} <- {:aud_valid, validate({:aud, jwt}, client)},
         {:nonce_valid, true} <- {:nonce_valid, validate({:nonce, jwt}, client)} do
      decoded_token = decode_token(client.id_token)
      {:ok, decoded_token}
    else
      {:verified, {false, _, _}} -> {:error, "The token provided could not be verified"}
      {:jwt, _} -> {:error, "Error parsing JWT"}
      {:expired, false} -> {:error, "The token is expired"}
      {:iss_valid, false} -> {:error, "The issuer cannot be verified"}
      {:aud_valid, false} -> {:error, "The token's audience cannot be verified"}
      {:nonce_valid, false} -> {:error, "The token's nonce cannot be verified"}
      _ -> {:error, "The token could not be verified"}
    end
  rescue
    _ -> {:error, "The token could not be verified"}
  end

  def decode_signature(token), do: JOSE.JWT.peek_protected(token)

  def response_type, do: Keyword.get(default_options(), :response_type)

  @spec decode_token(binary | {any, binary | map} | map) :: [any] | JOSE.JWT.t()
  def decode_token(token), do: JOSE.JWT.peek_payload(token)

  defp default_options(),
    do: Keyword.merge(@default_opts, Application.get_env(:ueberauth, __MODULE__, []))

  defp generate_nonce(length: length),
    do: :crypto.strong_rand_bytes(length) |> Base.url_encode64(padding: false)

  defp get_kid_from_token(token) do
    %JOSE.JWS{
      fields: %{
        "kid" => kid
      }
    } = decode_signature(token)

    kid
  end

  defp validate({type, %JOSE.JWT{} = jwt}, %Asgard.Client{} = client),
    do: do_validate({type, jwt.fields}, client)

  defp do_validate({:exp, token}, _client),
    do: is_integer(token["exp"]) and :os.system_time(:seconds) < token["exp"]

  defp do_validate({:iss, token}, _client) do
    host = Application.get_env(:ueberauth, Ueberauth.Strategy.Asgard.OpenID) |> Keyword.get(:host)
    host === token["iss"]
  end

  defp do_validate({:aud, token}, client) do
    case token["aud"] do
      aud when is_binary(aud) -> aud == client.client_id
      [aud] -> aud == client.client_id
      aud when is_list(aud) -> client.client_id in aud and token["azp"] == client.client_id
      _ -> false
    end
  end

  defp do_validate({:nonce, _token}, %Asgard.Client{nonce: nil}), do: true

  defp do_validate({:nonce, token}, %Asgard.Client{nonce: nonce}) do
    is_binary(token["nonce"]) and byte_size(token["nonce"]) == byte_size(nonce) and
      Plug.Crypto.secure_compare(token["nonce"], nonce)
  end
end
