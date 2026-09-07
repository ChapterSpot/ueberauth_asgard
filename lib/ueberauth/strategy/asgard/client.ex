defmodule Ueberauth.Strategy.Asgard.Client do
  @moduledoc ~S"""
  HTTP client for the Ueberauth Asgard OpenID Strategy

  ## Examples
  iex> client = %Ueberauth.Strategy.Asgard.Client{client_id: "x", client_secret: "x", redirect_uri: "https://url/callback"}

  iex> Ueberauth.Strategy.Asgard.Client.get_token(client, code)

  {:ok, %Ueberauth.Strategy.Asgard.Client{access_token: "abcdef", ...}}
  """

  use HTTPoison.Base
  require Logger

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
    case get("/certificates") do
      {:ok, response} ->
        response.body["keys"]

      {:error, response} ->
        {:error, response}
    end
  end

  def certificates!(), do: get!("/certificates").body["keys"]

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
        {:error, "Certificate not found by kid #{kid}"}

      {:error, error} ->
        {:error, error}

      certificate ->
        {:ok, {:certificate, certificate}}
    end
  end

  def certificates!(kid) do
    {:ok, {:certificate, certificate}} = certificates(kid)
    certificate
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

    case post("/token", {:form, params}, headers, recv_timeout: 10_000, timeout: 10_000) do
      {:ok, %{body: %{"error" => error}}} ->
        {:error, [error: error, error_message: "FSID token request failed"]}

      {:ok, %{body: %{"access_token" => access_token}} = response} ->
        response =
          Map.merge(client, %{
            access_token: access_token,
            refresh_token: response.body["refresh_token"],
            id_token: response.body["id_token"],
            scopes: token_scopes(response.body["scope"], client.scopes),
            expiry: response.body["expires_in"] |> calculate_expiry!()
          })

        {:ok, response}

      {:error, _error} ->
        {:error, [error: "unknown", error_message: "FSID token request failed"]}
    end
  end

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
    |> Enum.to_list()
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

  # -- Base callbacks

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

  def process_response_body(body), do: Poison.decode!(body)
end
