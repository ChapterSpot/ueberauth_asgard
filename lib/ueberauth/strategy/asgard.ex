defmodule Ueberauth.Strategy.Asgard do
  use Ueberauth.Strategy
  require Logger

  alias Ueberauth.Strategy.Asgard.{Client, Login, OpenID}
  alias Ueberauth.Auth.{Credentials, Extra, Info}
  alias Plug.Conn

  def handle_request!(conn) do
    options =
      conn
      |> options()
      |> Keyword.merge(redirect_uri: callback_url(conn))
      |> Keyword.put_new(:scopes, OpenID.scopes())

    options =
      Keyword.merge(
        options,
        email_hint: conn.params["email_hint"],
        acr_values: conn.params["acr_values"]
      )
      |> with_state_param(conn)

    {conn, options} =
      if Keyword.get(options, :response_type, OpenID.response_type()) == "code",
        do: Login.prepare(conn, options),
        else: {conn, options}

    authorize_url =
      options
      |> OpenID.authorize_url!()
      |> URI.to_string()

    redirect!(conn, authorize_url)
  end

  def handle_callback!(%Conn{params: %{"id_token" => token}} = conn) do
    if Keyword.get(options(conn), :response_type, OpenID.response_type()) == "code" do
      set_errors!(conn, [error("invalid_response_type", "Authorization code required")])
    else
      id_token_callback(conn, token)
    end
  end

  def handle_callback!(%Conn{params: %{"code" => code}} = conn) do
    case Login.consume(conn) do
      {:ok, conn, correlation} ->
        code_callback(conn, code, correlation)

      {:error, conn} ->
        set_errors!(conn, [error("invalid_login_state", "Login expired or could not be verified")])
    end
  end

  def handle_callback!(
        %Conn{params: %{"error" => "invalid_request"}} =
          conn
      ) do
    set_errors!(conn, [error("asgard", "FSID could not complete login")])
  end

  def handle_callback!(conn),
    do:
      set_errors!(conn, [
        error("missing_callback_params", "Expected login callback parameters were not received")
      ])

  defp id_token_callback(conn, token) do
    config = options(conn)

    client = %Client{
      client_id: Keyword.get(config, :client_id),
      client_secret: Keyword.get(config, :client_secret),
      id_token: token,
      redirect_uri: Keyword.get(config, :redirect_uri),
      scopes: Keyword.get(config, :scopes)
    }

    case OpenID.verify_token(client) do
      {:ok, %JOSE.JWT{fields: claims}} ->
        asgard_user =
          claims
          |> Map.take(~w(sub given_name family_name email amr))
          |> Map.new(fn {k, v} -> {String.to_atom(k), v} end)

        conn
        |> put_private(:asgard, client)
        |> put_private(:asgard_user, asgard_user)

      {:error, error_description} ->
        set_errors!(conn, [error("asgard", error_description)])
    end
  end

  defp code_callback(conn, code, correlation) do
    config = options(conn)

    options =
      [
        client_id: Keyword.get(config, :client_id),
        client_secret: Keyword.get(config, :client_secret),
        redirect_uri: callback_url(conn),
        token_endpoint_auth_method: Keyword.get(config, :token_endpoint_auth_method),
        code: code
      ] ++ correlation

    case OpenID.exchange_code_for_token(options) do
      {:ok, client} ->
        %{fields: claims} = OpenID.decode_token(client.id_token)

        asgard_user =
          claims
          |> Map.take(~w(sub given_name family_name email amr))
          |> Map.new(fn {k, v} -> {String.to_atom(k), v} end)

        conn
        |> put_private(:asgard, client)
        |> put_private(:asgard_user, asgard_user)

      {:error, error_description} ->
        set_errors!(conn, [error("asgard", error_description)])
    end
  end

  def handle_cleanup!(conn) do
    conn
    |> put_private(:asgard_user, nil)
    |> put_private(:asgard, nil)
  end

  def credentials(conn) do
    %Credentials{
      token: conn.private.asgard.access_token,
      refresh_token: conn.private.asgard.refresh_token,
      token_type: "Bearer",
      expires: true,
      expires_at: conn.private.asgard.expiry,
      scopes: conn.private.asgard.scopes,
      other: %{
        id_token: conn.private.asgard.id_token,
        amr: Map.get(conn.private.asgard_user, :amr)
      }
    }
  end

  def extra(conn) do
    %Extra{
      raw_info: %{
        access_token: conn.private.asgard.access_token,
        id_token: conn.private.asgard.id_token,
        expiry: conn.private.asgard.expiry
      }
    }
  end

  def info(conn) do
    asgard_user = conn.private.asgard_user

    %Info{
      first_name: Map.get(asgard_user, :given_name),
      last_name: Map.get(asgard_user, :family_name),
      email: Map.get(asgard_user, :email)
    }
  end

  def uid(conn), do: conn.private.asgard_user.sub
end
