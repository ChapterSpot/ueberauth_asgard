defmodule Ueberauth.Strategy.Asgard do
  use Ueberauth.Strategy
  require Logger

  alias Ueberauth.Strategy.Asgard.OpenID
  alias Ueberauth.Auth.{Credentials, Extra, Info}
  alias Plug.Conn

  def handle_request!(conn) do
    options =
      conn
      |> options()
      |> Keyword.merge(redirect_uri: callback_url(conn))
      |> maybe_email_hint(conn)

    Logger.debug("Ueberauth.Strategy.Asgard options: #{inspect(options)}")

    authorize_url = OpenID.authorize_url!(options)

    redirect!(conn, authorize_url)
  end

  def handle_callback!(%Conn{params: %{"code" => code}} = conn) do
    config = options(conn)

    options = [
      client_id: Keyword.get(config, :client_id),
      client_secret: Keyword.get(config, :client_secret),
      redirect_uri: callback_url(conn),
      code: code
    ]

    case OpenID.exchange_code_for_token(options) do
      {:ok, client} ->
        %{fields: claims} = OpenID.decode_token(client.id_token)
        asgard_user =
          claims
          |> Map.take(~w(sub given_name family_name email))
          |> Map.new(fn {k, v} -> {String.to_atom(k), v} end)

        conn
        |> put_private(:asgard, client)
        |> put_private(:asgard_user, asgard_user)

      {:error, error_description} ->
        set_errors!(conn, [error("asgard", error_description)])
    end
  end

  def handle_callback!(
        %Conn{params: %{"error" => "invalid_request", "error_description" => error_description}} =
          conn
      ) do
    set_errors!(conn, [error("asgard", error_description)])
  end

  def handle_callback!(conn),
    do: set_errors!(conn, [error("missing_id_token", "No id token received")])

  def handle_cleanup!(conn) do
    conn
    |> put_private(:asgard_user, nil)
    |> put_private(:asgard, nil)
  end

  def credentials(conn) do
    %Credentials{
      token: conn.private.asgard.access_token,
      token_type: "Bearer",
      expires: true,
      expires_at: conn.private.asgard.expiry,
      scopes: conn.private.asgard.scopes,
      other: %{
        id_token: conn.private.asgard.id_token
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

  defp maybe_email_hint(options, conn) do
    email =
      conn
      |> Plug.Conn.fetch_query_params()
      |> get_in([:query_params, :email_hint])

    if not is_nil(email), do: Keyword.merge(options, [email_hint: email]), else: options
  end
end
