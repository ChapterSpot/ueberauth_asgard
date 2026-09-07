defmodule Ueberauth.Strategy.Asgard.Login do
  @moduledoc "Per-browser correlation and S256 PKCE for authorization-code login."
  import Plug.Conn

  @session_key "asgard_code_login"
  @ttl 600

  def prepare(conn, opts) do
    verifier = random()

    login = %{
      "state" => Keyword.get(opts, :state) || random(),
      "nonce" => random(),
      "verifier" => verifier,
      "issued_at" => System.system_time(:second)
    }

    challenge = :crypto.hash(:sha256, verifier) |> Base.url_encode64(padding: false)

    {put_session(conn, @session_key, login),
     Keyword.merge(opts,
       state: login["state"],
       nonce: login["nonce"],
       code_challenge: challenge,
       code_challenge_method: "S256"
     )}
  end

  def consume(conn) do
    saved = get_session(conn, @session_key)
    conn = delete_session(conn, @session_key)
    now = System.system_time(:second)

    case saved do
      %{"state" => expected, "nonce" => nonce, "verifier" => verifier, "issued_at" => issued}
      when is_binary(expected) and is_binary(nonce) and is_binary(verifier) and is_integer(issued) ->
        actual = conn.params["state"]

        if is_binary(actual) and byte_size(actual) == byte_size(expected) and
             Plug.Crypto.secure_compare(actual, expected) and issued <= now and
             now - issued < @ttl do
          {:ok, conn, [nonce: nonce, code_verifier: verifier]}
        else
          {:error, conn}
        end

      _ ->
        {:error, conn}
    end
  end

  defp random, do: :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
end
