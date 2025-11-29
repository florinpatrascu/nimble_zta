defmodule NimbleZTA.TailscaleTest do
  use ExUnit.Case, async: true
  import Plug.Test
  import Plug.Conn
  alias NimbleZTA.Tailscale

  @moduletag unix: true
  @fields [:id, :name, :email]
  @name Context.Test.Tailscale
  @path "/localapi/v0/whois"

  def valid_user_response(conn, _) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(
      200,
      JSON.encode!(%{
        UserProfile: %{
          ID: 1_234_567_890,
          DisplayName: "John",
          LoginName: "john@example.org"
        }
      })
    )
  end

  def invalid_user_response(conn, _) do
    conn
    |> send_resp(404, "no match for IP:port")
  end

  @moduletag bypass: &__MODULE__.valid_user_response/2
  setup {TestHelper, :bypass}

  setup context do
    conn = %{conn(:get, @path) | remote_ip: {151, 236, 219, 228}}

    options = [
      name: @name,
      identity_key: "http://localhost:#{context.port}"
    ]

    {:ok, options: options, conn: conn}
  end

  test "returns the user when it's valid", %{options: options, conn: conn} do
    start_supervised!({Tailscale, options})
    {_conn, user} = Tailscale.authenticate(@name, conn, @fields)
    assert %{id: "1234567890", email: "john@example.org", name: "John"} = user
  end

  @tag :tmp_dir
  test "returns valid user via unix socket", %{options: options, conn: conn, tmp_dir: tmp_dir} do
    socket = Path.relative_to_cwd("#{tmp_dir}/bandit.sock")
    options = Keyword.put(options, :identity_key, socket)
    start_supervised!({Bandit, plug: &valid_user_response/2, ip: {:local, socket}, port: 0})
    start_supervised!({Tailscale, options})
    {_conn, user} = Tailscale.authenticate(@name, conn, @fields)
    assert %{id: "1234567890", email: "john@example.org", name: "John"} = user
  end

  test "raises when configured with missing unix socket", %{options: options} do
    Process.flag(:trap_exit, true)
    options = Keyword.put(options, :identity_key, "./invalid-socket.sock")

    assert ExUnit.CaptureLog.capture_log(fn ->
             {:error, _} = start_supervised({Tailscale, options})
           end) =~ "Tailscale socket does not exist"
  end

  @tag bypass: &__MODULE__.invalid_user_response/2
  test "returns nil when it's invalid", %{options: options} do
    conn = %{conn(:get, @path) | remote_ip: {151, 236, 219, 229}}

    start_supervised!({Tailscale, options})
    assert {_conn, nil} = Tailscale.authenticate(@name, conn, @fields)
  end

  @tag bypass: &__MODULE__.invalid_user_response/2
  test "includes an authorization header when userinfo is provided", %{
    options: options,
    port: port,
    conn: conn
  } do
    options = Keyword.put(options, :identity_key, "http://:foobar@localhost:#{port}")

    start_supervised!({Tailscale, options})
    assert {_conn, nil} = Tailscale.authenticate(@name, conn, @fields)
  end
end
