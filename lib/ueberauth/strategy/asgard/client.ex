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

  defstruct [:client_id,
            :client_secret,
            :access_token,
            :id_token,
            :redirect_uri,
            :id_token,
            :scopes,
            :expiry]

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
        {:error, error}
          -> {:error, error}

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

  def get_token!(%Asgard.Client{} = client, code) do
    {:ok, client} = get_token(client, code)
    client
  end

  def get_token(%Asgard.Client{} = client, code) do
    params =
      {:token, Map.merge(client, %{code: code, grant_type: "authorization_code"})}
      |> build_params()

    case post("/token", {:form, params}, post_headers()) do
      {:ok, %{body: %{"error" => error}} = response} ->
        {:error, [{:error, error}, {:error_message, response.body["error_description"]}]}

      {:ok, %{body: %{"access_token" => access_token}} = response} ->
        response =
          client |>
          Map.merge(%{
            access_token: access_token,
            id_token: response.body["id_token"],
            scopes: response.body["scope"] |> String.split(),
            expiry: response.body["expires_in"] |> calculate_expiry!()
          })

        {:ok, response}

      {:error, error} ->
        {:error, [{:error, "unknown"}, {:error_message, error}]}
    end
  end

  def logout(%{id_token_hint: id_token_hint} = params) when is_nil(id_token_hint) === false and byte_size(id_token_hint) > 0 do
    session_end_endpoint = Asgard.OpenID.logout_url()

    config = Application.get_env(:ueberauth, Asgard.OpenID, [])
    post_logout_redirect_uri = Keyword.get(config, :post_logout_redirect_uri)

    query_params = [id_token_hint: id_token_hint]

    query_params =
      if (post_logout_redirect_uri),
        do: query_params ++ [post_logout_redirect_uri: post_logout_redirect_uri],
        else: query_params

    query_params =
      if (post_logout_redirect_uri && Map.has_key?(params, :state)),
        do: query_params ++ [state: params.state],
        else: query_params

    query_params |> case do
      [_] -> session_end_endpoint
      [_ | _] -> session_end_endpoint <> "?" <> URI.encode_query(query_params)
    end
  end

  defp build_params({:token, %{} = params}) do
    param_whitelist = ~w(code client_id client_secret grant_type redirect_uri)a

    params
    |> Map.take(param_whitelist)
    |> Enum.to_list()
  end

  defp post_headers(), do: %{"Content-Type" => "application/x-www-form-urlencoded"}

  defp calculate_expiry!(expiry) do
    now = DateTime.utc_now() |> DateTime.to_unix()
    now = now + expiry

    DateTime.from_unix!(now)
  end

  # -- Base callbacks

  def process_url(endpoint) do
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
