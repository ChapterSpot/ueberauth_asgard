defmodule Ueberauth.Strategy.Asgard do
  use Ueberauth.Strategy, uid_field: :sub

  alias Ueberauth.Strategy.Asgard.OpenID
  alias Ueberauth.Auth.{Credentials, Extra, Info}
  alias Plug.Conn

  def handle_request!(conn) do
    authorize_url =
      conn.params
      |> OpenID.authorize_url!

    redirect!(conn, authorize_url)
  end

  def handle_callback!(%Conn{params: %{"id_token" => id_token}} = conn) do
    case OpenID.verify_token(id_token) do
      {:ok, payload} ->
        payload = payload |> Poison.encode!
        put_private(conn, :asgard_user, payload)

      {:error, error} ->
        set_errors!(conn, [error("asgard", error)])
    end
  end

  def handle_callback!(conn), do: set_errors!(conn, [error("missing_id_token", "No id token received")])
end
