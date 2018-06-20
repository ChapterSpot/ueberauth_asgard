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


        put_private(conn, :asgard_user, asgard_user)

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
    conn |> put_private(:asgard_user, nil)
  end
end
