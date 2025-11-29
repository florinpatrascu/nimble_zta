defmodule NimbleZTA.PassThrough do
  @moduledoc """
  A pass-through Zero Trust Authentication (recommended for dev/testing/staging).

  Add it to your supervision tree as:

      {NimbleZTA.PassThrough, name: MyApp.ZTA}

  And then call `NimbleZTA.PassThrough.authenticate(MyApp.ZTA, conn)` in the
  Plug you want to enable this authentication.
  """
  @behaviour NimbleZTA

  @impl true
  def child_spec(_opts) do
    %{id: __MODULE__, start: {Function, :identity, [:ignore]}}
  end

  @impl true
  def authenticate(_name, conn, _opts \\ []) do
    {conn, %{}}
  end
end
