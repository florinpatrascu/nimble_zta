defmodule NimbleZTA.BasicAuth do
  @moduledoc """
  Use basic authentication as Zero Trust Authentication (recommended for dev/tests/staging).

  Add it to your supervision tree as:

      {NimbleZTA.BasicAuth, name: MyApp.ZTA, identity_key: "username:password"}

  Where "username:password" is the desired "username" and "password" combo.

  And then call `NimbleZTA.BasicAuth.authenticate(MyApp.ZTA, conn)` in the
  Plug you want to enable this authentication.
  """
  @behaviour NimbleZTA

  @impl true
  def child_spec(opts) do
    %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}}
  end

  @doc false
  def start_link(options) do
    name = Keyword.fetch!(options, :name)
    identity_key = Keyword.fetch!(options, :identity_key)
    [username, password] = String.split(identity_key, ":", parts: 2)

    NimbleZTA.put(name, {username, password})
    :ignore
  end

  @impl true
  def authenticate(name, conn, _opts \\ []) do
    {username, password} = NimbleZTA.get(name)
    conn = Plug.BasicAuth.basic_auth(conn, username: username, password: password)

    if conn.halted do
      {conn, nil}
    else
      {conn, %{}}
    end
  end
end
