defmodule Ueberauth.Strategy.Asgard.Client do
  @moduledoc ~S"""
  HTTP client for the Ueberauth Asgard OpenID Strategy

  ## Examples
  iex> client = %Ueberauth.Strategy.Asgard.Client{client_id: "x", client_secret: "x", redirect_uri: "https://url/callback"}

  iex> Ueberauth.Strategy.Asgard.Client.get_token(client, code)

  {:ok, %Ueberauth.Strategy.Asgard.Client{access_token: "abcdef", ...}}
  """

  @timeout 10_000
  @oauth_errors ~w(invalid_request invalid_client invalid_grant unauthorized_client unsupported_grant_type invalid_scope server_error temporarily_unavailable)

  alias Ueberauth.Strategy.Asgard

  @derive {Inspect,
           except: [
             :client_secret,
             :access_token,
             :refresh_token,
             :id_token,
             :code_verifier,
             :nonce
           ]}
  defstruct [
    :client_id,
    :client_secret,
    :access_token,
    :refresh_token,
    :code_verifier,
    :nonce,
    :token_endpoint_auth_method,
    :id_token,
    :redirect_uri,
    :scopes,
    :expiry
  ]

  @type t :: %__MODULE__{
          client_id: String.t() | nil,
          client_secret: String.t() | nil,
          access_token: String.t() | nil,
          id_token: String.t() | nil,
          redirect_uri: String.t() | nil,
          scopes: List.t() | nil,
          expiry: DateTime.t() | nil
        }

  def certificates() do
    case request(:get, "/certificates") do
      {:ok, status, %{"keys" => keys}} when status in 200..299 and is_list(keys) ->
        if Enum.all?(keys, &is_map/1), do: keys, else: {:error, :invalid_certificates}

      _ ->
        {:error, :certificates_request_failed}
    end
  end

  def certificates!() do
    case certificates() do
      {:error, _} -> raise "FSID certificates request failed"
      certificates -> certificates
    end
  end

  def certificates(kid) do
    certificate =
      case certificates() do
        {:error, error} ->
          {:error, error}

        certificates ->
          certificates
          |> Enum.find(fn cert -> cert["kid"] === kid end)
      end

    case certificate do
      nil ->
        {:error, "Certificate not found"}

      {:error, error} ->
        {:error, error}

      certificate ->
        {:ok, {:certificate, certificate}}
    end
  end

  def certificates!(kid) do
    case certificates(kid) do
      {:ok, {:certificate, certificate}} -> certificate
      {:error, _} -> raise "FSID certificate lookup failed"
    end
  end

  def generate_email_hint_signature(email, options) do
    client_secret = Keyword.get(options, :client_secret)

    if not is_nil(client_secret) do
      do_email_hint_sig(client_secret, email)
    end
  end

  if Code.ensure_loaded?(:crypto) and function_exported?(:crypto, :hmac, 3) do
    defp do_email_hint_sig(secret, email),
      do: :crypto.hmac(:sha256, secret, email) |> Base.encode64()
  else
    defp do_email_hint_sig(secret, email),
      do: :crypto.mac(:hmac, :sha256, secret, email) |> Base.encode64()
  end

  def get_token!(%Asgard.Client{} = client, code) do
    {:ok, client} = get_token(client, code)
    client
  end

  def get_token(%Asgard.Client{} = client, code) do
    params =
      {:token, Map.merge(client, %{code: code, grant_type: "authorization_code"})}
      |> build_params()

    {params, headers} = token_auth(params, client)

    case request(:post, "/token", form: params, headers: headers) do
      {:ok, _, %{"error" => error}} ->
        token_error(if error in @oauth_errors, do: error, else: "unknown")

      {:ok, status, %{"access_token" => access_token, "expires_in" => expiry} = body}
      when status in 200..299 and is_binary(access_token) and is_integer(expiry) and expiry >= 0 ->
        if valid_token_fields?(body) do
          {:ok,
           %{
             client
             | access_token: access_token,
               refresh_token: body["refresh_token"],
               id_token: body["id_token"],
               scopes: token_scopes(body["scope"], client.scopes),
               expiry: calculate_expiry!(expiry)
           }}
        else
          token_error("unknown")
        end

      _ ->
        token_error("unknown")
    end
  rescue
    _ -> token_error("unknown")
  end

  defp valid_token_fields?(body) do
    Enum.all?(["refresh_token", "id_token", "scope"], fn key ->
      is_nil(body[key]) or is_binary(body[key])
    end)
  end

  defp token_error(error),
    do: {:error, [error: error, error_message: "FSID token request failed"]}

  defp token_scopes(nil, requested) when is_list(requested), do: requested
  defp token_scopes(nil, requested), do: String.split(requested || "")
  defp token_scopes(scope, _requested), do: String.split(scope)

  def logout(nil), do: nil

  def logout(%{id_token_hint: id_token_hint} = params)
      when is_nil(id_token_hint) === false and byte_size(id_token_hint) > 0 do
    session_end_endpoint = Asgard.OpenID.logout_url()

    config = Application.get_env(:ueberauth, Asgard.OpenID, [])
    post_logout_redirect_uri = Keyword.get(config, :post_logout_redirect_uri)

    query_params = [id_token_hint: id_token_hint]

    query_params =
      if post_logout_redirect_uri,
        do: query_params ++ [post_logout_redirect_uri: post_logout_redirect_uri],
        else: query_params

    query_params =
      if post_logout_redirect_uri && Map.has_key?(params, :state),
        do: query_params ++ [state: params.state],
        else: query_params

    query_params
    |> case do
      [_] -> session_end_endpoint
      [_ | _] -> session_end_endpoint <> "?" <> URI.encode_query(query_params)
    end
  end

  def logout(_), do: nil

  defp build_params({:token, %{} = params}) do
    param_whitelist = ~w(code client_id client_secret grant_type redirect_uri code_verifier)a

    params
    |> Map.take(param_whitelist)
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
  end

  defp post_headers(), do: %{"Content-Type" => "application/x-www-form-urlencoded"}

  defp token_auth(params, %{token_endpoint_auth_method: "client_secret_basic"} = client) do
    credentials =
      URI.encode_www_form(client.client_id) <> ":" <> URI.encode_www_form(client.client_secret)

    {Keyword.drop(params, [:client_id, :client_secret]),
     Map.put(post_headers(), "Authorization", "Basic " <> Base.encode64(credentials))}
  end

  defp token_auth(params, _client), do: {params, post_headers()}

  defp calculate_expiry!(expiry) do
    now = DateTime.utc_now() |> DateTime.to_unix()
    now = now + expiry

    DateTime.from_unix!(now)
  end

  defp request(method, endpoint, options \\ []) do
    options =
      Keyword.merge(options,
        method: method,
        url: process_request_url(endpoint),
        retry: false,
        redirect: false,
        decode_body: false,
        receive_timeout: timeout(:receive_timeout),
        pool_timeout: timeout(:connect_timeout),
        connect_options: [timeout: timeout(:connect_timeout)]
      )

    with {:ok, %{status: status, body: body}} <- Req.request(options),
         {:ok, decoded} <- Poison.decode(body) do
      {:ok, status, decoded}
    else
      _ -> {:error, :request_failed}
    end
  rescue
    _ -> {:error, :request_failed}
  catch
    :exit, _ -> {:error, :request_failed}
  end

  defp timeout(key) do
    value = Application.get_env(:ueberauth, Asgard.OpenID, []) |> Keyword.get(key, @timeout)
    if is_integer(value) and value > 0, do: min(value, @timeout), else: @timeout
  end

  def process_request_url(endpoint) do
    config = Application.get_env(:ueberauth, Asgard.OpenID)

    url = Keyword.get(config, :host)
    url = Keyword.get(config, :internal_host, url) || url

    endpoint =
      case endpoint do
        <<"/" <> _>> ->
          endpoint

        _ ->
          "/" <> endpoint
      end

    url <> endpoint
  end
end
