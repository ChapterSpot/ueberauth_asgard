defmodule UeberauthAsgard.ClientTest do
  use ExUnit.Case, async: false
  import Plug.Conn
  import ExUnit.CaptureLog
  alias Ueberauth.Strategy.Asgard.{Client, OpenID}

  setup do
    bypass = Bypass.open()
    previous = Application.get_env(:ueberauth, OpenID)
    host = "http://localhost:#{bypass.port}"
    Application.put_env(:ueberauth, OpenID, host: host, internal_host: host)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:ueberauth, OpenID, previous),
        else: Application.delete_env(:ueberauth, OpenID)
    end)

    %{bypass: bypass}
  end

  test "JWKS list and kid lookup use real HTTP", %{bypass: bypass} do
    keys = [%{"kid" => "a", "kty" => "RSA"}, %{"kid" => "b", "kty" => "RSA"}]
    Bypass.expect(bypass, "GET", "/certificates", &json(&1, 200, %{keys: keys}))
    assert Client.certificates() == keys
    assert Client.certificates!() == keys
    assert Client.certificates("b") == {:ok, {:certificate, Enum.at(keys, 1)}}
    assert Client.certificates!("b") == Enum.at(keys, 1)
    assert {:error, "Certificate not found"} = Client.certificates("secret-kid")
  end

  test "malformed, missing and non-2xx JWKS responses fail safely", %{bypass: bypass} do
    for {status, body} <- [
          {200, "not-json-private-secret"},
          {200, Poison.encode!(%{keys: "private-secret"})},
          {200, Poison.encode!(%{keys: ["private-secret"]})},
          {200, "{}"},
          {503, Poison.encode!(%{keys: []})}
        ] do
      Bypass.expect(bypass, "GET", "/certificates", &send_resp(&1, status, body))
      assert {:error, reason} = Client.certificates()
      refute inspect(reason) =~ "private-secret"
      assert_raise RuntimeError, "FSID certificates request failed", &Client.certificates!/0
    end
  end

  test "Basic credentials and form values retain exact encoding and returned refresh credentials",
       %{bypass: bypass} do
    client = %Client{
      client_id: "id: +/",
      client_secret: "private-secret: +/",
      code_verifier: "private-verifier+/?",
      redirect_uri: "https://app.test/callback?one=a+b&two=%2F",
      token_endpoint_auth_method: "client_secret_basic",
      scopes: ["openid", "offline_access"]
    }

    Bypass.expect_once(bypass, "POST", "/token", fn conn ->
      credentials =
        URI.encode_www_form(client.client_id) <> ":" <> URI.encode_www_form(client.client_secret)

      assert get_req_header(conn, "authorization") == ["Basic " <> Base.encode64(credentials)]
      assert [content_type] = get_req_header(conn, "content-type")
      assert content_type =~ "application/x-www-form-urlencoded"
      {:ok, body, conn} = read_body(conn)

      assert URI.decode_query(body) == %{
               "code" => "private-code+&=",
               "code_verifier" => client.code_verifier,
               "redirect_uri" => client.redirect_uri,
               "grant_type" => "authorization_code"
             }

      json(conn, 200, %{
        access_token: "private-access",
        refresh_token: "private-refresh",
        id_token: "private-id",
        expires_in: 300
      })
    end)

    before = DateTime.utc_now()
    assert {:ok, result} = Client.get_token(client, "private-code+&=")
    assert result.refresh_token == "private-refresh"
    assert result.access_token == "private-access"
    assert result.id_token == "private-id"
    assert result.scopes == ["openid", "offline_access"]
    assert DateTime.diff(result.expiry, before) in 299..301
    refute inspect(result) =~ "private-"
  end

  test "legacy client-secret POST and granted scopes remain supported", %{bypass: bypass} do
    Bypass.expect_once(bypass, "POST", "/token", fn conn ->
      assert get_req_header(conn, "authorization") == []
      {:ok, body, conn} = read_body(conn)

      assert URI.decode_query(body) == %{
               "client_id" => "legacy",
               "client_secret" => "private-secret",
               "code" => "private-code",
               "grant_type" => "authorization_code"
             }

      json(conn, 200, %{access_token: "access", expires_in: 300, scope: "openid email"})
    end)

    assert {:ok, %{scopes: ["openid", "email"]}} =
             Client.get_token(
               %Client{client_id: "legacy", client_secret: "private-secret"},
               "private-code"
             )
  end

  test "single-use exchanges do not retry a transient server failure", %{bypass: bypass} do
    Bypass.expect_once(bypass, "POST", "/token", fn conn ->
      json(conn, 503, %{error: "temporarily_unavailable", error_description: "private-secret"})
    end)

    assert {:error, [error: "temporarily_unavailable", error_message: _]} =
             Client.get_token(%Client{}, "private-code")
  end

  test "redirects never forward an exchange to another endpoint", %{bypass: bypass} do
    Bypass.expect_once(bypass, "POST", "/token", fn conn ->
      conn |> put_resp_header("location", "/unexpected") |> send_resp(307, "")
    end)

    assert {:error, _} =
             Client.get_token(%Client{client_secret: "private-secret"}, "private-code")
  end

  test "untrusted errors and malformed successes never expose response or request data", %{
    bypass: bypass
  } do
    client = %Client{client_secret: "private-secret", code_verifier: "private-verifier"}

    log =
      capture_log(fn ->
        for {status, body} <- [
              {400,
               Poison.encode!(%{error: "private-secret", error_description: "private-verifier"})},
              {200, "not-json-private-secret"},
              {200, "{}"},
              {200,
               Poison.encode!(%{access_token: "private-access", expires_in: "private-secret"})},
              {200,
               Poison.encode!(%{
                 access_token: "private-access",
                 expires_in: 300,
                 scope: %{secret: "private-secret"}
               })},
              {500, Poison.encode!(%{access_token: "private-access", expires_in: 300})}
            ] do
          Bypass.expect(bypass, "POST", "/token", &send_resp(&1, status, body))

          assert {:error, [error: "unknown", error_message: "FSID token request failed"]} =
                   result = Client.get_token(client, "private-code")

          refute inspect(result) =~ "private-"
        end
      end)

    refute log =~ "private-"
  end

  test "connection failures return inspect-safe errors", %{bypass: bypass} do
    Bypass.down(bypass)

    log =
      capture_log(fn ->
        assert {:error, _} =
                 result =
                 Client.get_token(
                   %Client{client_secret: "private-secret", code_verifier: "private-verifier"},
                   "private-code"
                 )

        refute inspect(result) =~ "private-"
        assert {:error, :certificates_request_failed} = Client.certificates()
      end)

    refute log =~ "private-"
  end

  test "a delayed real response hits the finite receive timeout" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)

    server =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener)
        {:ok, _request} = :gen_tcp.recv(socket, 0, 2_000)
        :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")

        receive do
          :stop -> :gen_tcp.close(socket)
        after
          3_000 -> :gen_tcp.close(socket)
        end
      end)

    Application.put_env(:ueberauth, OpenID, host: "http://localhost:#{port}", receive_timeout: 50)

    try do
      start = System.monotonic_time(:millisecond)
      assert {:error, _} = Client.get_token(%Client{}, "private-code")
      assert System.monotonic_time(:millisecond) - start < 2_000
    after
      send(server.pid, :stop)
      Task.await(server)
      :gen_tcp.close(listener)
    end
  end

  defp json(conn, status, body) do
    conn |> put_resp_content_type("application/json") |> send_resp(status, Poison.encode!(body))
  end
end
