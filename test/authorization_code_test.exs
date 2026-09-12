defmodule UeberauthAsgard.AuthorizationCodeTest do
  use ExUnit.Case, async: false
  import Plug.Conn
  import ExUnit.CaptureLog
  alias Ueberauth.Strategy.Asgard.{Client, Login, OpenID, JWS}
  alias Ueberauth.Strategy.Asgard

  setup do
    bypass = Bypass.open()
    host = "http://localhost:#{bypass.port}"
    previous = Application.get_env(:ueberauth, OpenID)

    Application.put_env(:ueberauth, OpenID,
      host: host,
      internal_host: host,
      response_type: "code"
    )

    on_exit(fn ->
      if previous,
        do: Application.put_env(:ueberauth, OpenID, previous),
        else: Application.delete_env(:ueberauth, OpenID)
    end)

    jwk = JOSE.JWK.generate_key({:rsa, 2048})
    kid = Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)
    JWS.get_jwk_by_kid({host, kid}, fn -> jwk end)
    %{bypass: bypass, host: host, jwk: jwk, kid: kid}
  end

  test "S256 login binds state and nonce without exposing the verifier or client secret" do
    conn = Plug.Test.conn(:get, "/auth/asgard") |> Plug.Test.init_test_session(%{})

    {conn, opts} =
      Login.prepare(conn,
        client_id: "builder-prod",
        client_secret: "private-client-secret",
        scopes: "openid profile email offline_access",
        redirect_uri: "https://builder.test/callback"
      )

    log =
      capture_log(fn ->
        query = OpenID.authorize_url!(opts).query |> URI.decode_query()
        assert query["response_type"] == "code"
        assert query["code_challenge_method"] == "S256"
        assert query["scope"] =~ "offline_access"
        refute Map.has_key?(query, "code_verifier")
        refute Map.has_key?(query, "client_secret")
        callback = %{conn | params: %{"state" => query["state"]}}
        assert {:ok, consumed, correlation} = Login.consume(callback)

        expected =
          :crypto.hash(:sha256, correlation[:code_verifier]) |> Base.url_encode64(padding: false)

        assert query["code_challenge"] == expected
        assert query["nonce"] == correlation[:nonce]
        assert {:error, _} = Login.consume(consumed)
      end)

    refute log =~ "private-client-secret"
    refute log =~ get_session(conn, "asgard_code_login")["verifier"]
  end

  test "wrong, absent, expired and future login state are rejected" do
    conn = Plug.Test.conn(:get, "/auth/asgard") |> Plug.Test.init_test_session(%{})
    {conn, opts} = Login.prepare(conn, [])

    for state <- [nil, "wrong"] do
      assert {:error, cleared} = Login.consume(%{conn | params: %{"state" => state}})
      assert get_session(cleared, "asgard_code_login") == nil
    end

    saved = get_session(conn, "asgard_code_login")

    for time <- [System.system_time(:second) - 601, System.system_time(:second) + 60] do
      callback = conn |> put_session("asgard_code_login", Map.put(saved, "issued_at", time))
      assert {:error, _} = Login.consume(%{callback | params: %{"state" => opts[:state]}})
    end
  end

  test "code exchange transmits verifier with Basic auth and preserves rotating credentials",
       ctx do
    token = token(ctx, %{"nonce" => "expected-nonce"})

    Bypass.expect_once(ctx.bypass, "POST", "/token", fn conn ->
      assert get_req_header(conn, "authorization") == [
               "Basic " <> Base.encode64("builder-prod:private-client-secret")
             ]

      {:ok, body, conn} = read_body(conn)

      assert URI.decode_query(body) == %{
               "grant_type" => "authorization_code",
               "code" => "one-time-code",
               "code_verifier" => "private-verifier",
               "redirect_uri" => "https://builder.test/callback"
             }

      conn
      |> put_resp_content_type("application/json")
      |> send_resp(
        200,
        Poison.encode!(%{
          access_token: "private-access-token",
          refresh_token: "private-refresh-token",
          id_token: token,
          scope: "openid email offline_access",
          expires_in: 300
        })
      )
    end)

    log =
      capture_log(fn ->
        assert {:ok, client} =
                 OpenID.exchange_code_for_token(
                   client_id: "builder-prod",
                   client_secret: "private-client-secret",
                   code: "one-time-code",
                   code_verifier: "private-verifier",
                   nonce: "expected-nonce",
                   token_endpoint_auth_method: "client_secret_basic",
                   redirect_uri: "https://builder.test/callback"
                 )

        assert client.access_token == "private-access-token"
        assert client.refresh_token == "private-refresh-token"
        assert "offline_access" in client.scopes
        refute inspect(client) =~ "private-"
      end)

    refute log =~ "private-"
  end

  test "verified tokens require matching nonce, issuer, audience, signature and expiry", ctx do
    for overrides <- [
          %{"nonce" => "wrong"},
          %{"nonce" => nil},
          %{"iss" => "https://wrong.test"},
          %{"aud" => "other"},
          %{"exp" => System.system_time(:second) - 1}
        ] do
      client = %Client{
        client_id: "builder-prod",
        nonce: "expected-nonce",
        id_token: token(ctx, overrides)
      }

      assert {:error, _} = OpenID.verify_token(client)
    end

    other_key = JOSE.JWK.generate_key({:rsa, 2048})
    bad_signature = token(%{ctx | jwk: other_key}, %{})

    assert {:error, _} =
             OpenID.verify_token(%Client{
               client_id: "builder-prod",
               nonce: "expected-nonce",
               id_token: bad_signature
             })

    assert {:error, _} = OpenID.verify_token(%Client{id_token: "malformed"})
  end

  test "the complete strategy callback returns verified user and refresh credentials", ctx do
    provider =
      {Asgard,
       [
         client_id: "builder-prod",
         client_secret: "private-client-secret",
         scopes: "openid profile email offline_access",
         response_type: "code",
         token_endpoint_auth_method: "client_secret_basic"
       ]}

    request =
      Plug.Test.conn(:get, "https://builder.test/auth/asgard")
      |> Plug.Test.init_test_session(%{})
      |> fetch_query_params()
      |> Ueberauth.run_request(:asgard, provider)

    [location] = get_resp_header(request, "location")
    query = location |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    saved = get_session(request, "asgard_code_login")
    assert query["state"] == saved["state"]
    assert query["redirect_uri"] == "https://builder.test/auth/asgard/callback"
    ctx = %{ctx | kid: "uncached-" <> ctx.kid}
    {_, public_key} = JOSE.JWK.to_public_map(ctx.jwk)

    Bypass.expect_once(ctx.bypass, "GET", "/certificates", fn conn ->
      conn
      |> put_resp_content_type("application/json")
      |> send_resp(200, Poison.encode!(%{keys: [Map.put(public_key, "kid", ctx.kid)]}))
    end)

    id_token = token(ctx, %{"nonce" => query["nonce"]})

    Bypass.expect_once(ctx.bypass, "POST", "/token", fn conn ->
      {:ok, body, conn} = read_body(conn)
      params = URI.decode_query(body)
      assert params["code_verifier"] == saved["verifier"]
      assert params["redirect_uri"] == query["redirect_uri"]
      refute Map.has_key?(params, "client_secret")

      conn
      |> put_resp_content_type("application/json")
      |> send_resp(
        200,
        Poison.encode!(%{
          access_token: "private-access",
          refresh_token: "private-refresh",
          id_token: id_token,
          expires_in: 300
        })
      )
    end)

    callback =
      Plug.Test.conn(
        :get,
        "https://builder.test/auth/asgard/callback?" <>
          URI.encode_query(%{"code" => "one-time-code", "state" => query["state"]})
      )
      |> Plug.Test.recycle_cookies(request)
      |> Plug.Test.init_test_session(%{"asgard_code_login" => saved})
      |> fetch_query_params()
      |> fetch_cookies()
      |> Ueberauth.run_callback(:asgard, provider)

    refute Map.has_key?(callback.assigns, :ueberauth_failure)
    assert callback.assigns.ueberauth_auth.uid == "user-subject"
    assert callback.assigns.ueberauth_auth.info.email == "user@chapterspot.com"
    assert callback.assigns.ueberauth_auth.credentials.token == "private-access"
    assert callback.assigns.ueberauth_auth.credentials.refresh_token == "private-refresh"
    assert callback.assigns.ueberauth_auth.credentials.scopes == String.split(query["scope"])
    assert get_session(callback, "asgard_code_login") == nil
    assert callback.private.asgard == nil
  end

  test "code login rejects an implicit callback even with a valid state cookie", ctx do
    provider = {Asgard, [client_id: "builder-prod", response_type: "code"]}

    request =
      Plug.Test.conn(:get, "https://builder.test/auth/asgard")
      |> Plug.Test.init_test_session(%{})
      |> fetch_query_params()
      |> Ueberauth.run_request(:asgard, provider)

    saved = get_session(request, "asgard_code_login")

    callback =
      Plug.Test.conn(
        :get,
        "https://builder.test/auth/asgard/callback?" <>
          URI.encode_query(%{
            "id_token" => token(ctx, %{"nonce" => saved["nonce"]}),
            "state" => saved["state"]
          })
      )
      |> Plug.Test.recycle_cookies(request)
      |> Plug.Test.init_test_session(%{"asgard_code_login" => saved})
      |> fetch_query_params()
      |> fetch_cookies()
      |> Ueberauth.run_callback(:asgard, provider)

    assert [%{message_key: "invalid_response_type"}] = callback.assigns.ueberauth_failure.errors
    refute Map.has_key?(callback.assigns, :ueberauth_auth)
  end

  test "explicit legacy ID-token callback still accepts a verified token", ctx do
    provider = {Asgard, [response_type: "id_token", client_id: "builder-prod"]}

    request =
      Plug.Test.conn(:get, "https://builder.test/auth/asgard")
      |> Plug.Test.init_test_session(%{})
      |> fetch_query_params()
      |> Ueberauth.run_request(:asgard, provider)

    [location] = get_resp_header(request, "location")
    query = location |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

    result =
      Plug.Test.conn(
        :get,
        "https://builder.test/auth/asgard/callback?" <>
          URI.encode_query(%{"id_token" => token(ctx, %{}), "state" => query["state"]})
      )
      |> Plug.Test.recycle_cookies(request)
      |> Plug.Test.init_test_session(%{})
      |> fetch_query_params()
      |> fetch_cookies()
      |> Ueberauth.run_callback(:asgard, provider)

    refute Map.has_key?(result.assigns, :ueberauth_failure)
    assert result.assigns.ueberauth_auth.uid == "user-subject"
  end

  test "token errors retain the code without exposing provider descriptions", ctx do
    Bypass.expect_once(ctx.bypass, "POST", "/token", fn conn ->
      conn
      |> put_resp_content_type("application/json")
      |> send_resp(
        400,
        Poison.encode!(%{
          error: "invalid_grant",
          error_description: "private-token-and-provider-details"
        })
      )
    end)

    log =
      capture_log(fn ->
        assert {:error, [error: "invalid_grant", error_message: "FSID token request failed"]} =
                 Client.get_token(%Client{client_id: "builder-prod"}, "code")
      end)

    refute log =~ "private-token-and-provider-details"
  end

  test "explicit granted scopes replace requested scopes", ctx do
    Bypass.expect_once(ctx.bypass, "POST", "/token", fn conn ->
      conn
      |> put_resp_content_type("application/json")
      |> send_resp(
        200,
        Poison.encode!(%{access_token: "access", scope: "openid", expires_in: 300})
      )
    end)

    assert {:ok, %{scopes: ["openid"]}} =
             Client.get_token(
               %Client{client_id: "builder-prod", scopes: ["openid", "offline_access"]},
               "code"
             )
  end

  test "issuer validation uses default configuration when none is installed", ctx do
    Application.delete_env(:ueberauth, OpenID)
    host = OpenID.authorize_url!() |> Map.fetch!(:host)
    issuer = "https://" <> host
    JWS.get_jwk_by_kid({issuer, ctx.kid}, fn -> ctx.jwk end)

    assert {:ok, _} =
             OpenID.verify_token(%Client{
               client_id: "builder-prod",
               nonce: "expected-nonce",
               id_token: token(ctx, %{"iss" => issuer})
             })
  end

  test "missing callback parameters report a neutral error for both response types" do
    for response_type <- ["code", "id_token"] do
      conn =
        Plug.Test.conn(:get, "/auth/asgard/callback")
        |> Plug.Test.init_test_session(%{})
        |> fetch_query_params()
        |> put_private(:ueberauth_strategy, {Asgard, [response_type: response_type]})
        |> Asgard.handle_callback!()

      assert [%{message_key: "missing_callback_params"}] = conn.assigns.ueberauth_failure.errors
    end
  end

  defp token(ctx, overrides) do
    claims =
      Map.merge(
        %{
          "sub" => "user-subject",
          "email" => "user@chapterspot.com",
          "iss" => ctx.host,
          "aud" => "builder-prod",
          "nonce" => "expected-nonce",
          "exp" => System.system_time(:second) + 300
        },
        overrides
      )

    JOSE.JWT.sign(ctx.jwk, %{"alg" => "RS256", "kid" => ctx.kid}, claims)
    |> JOSE.JWS.compact()
    |> elem(1)
  end
end
