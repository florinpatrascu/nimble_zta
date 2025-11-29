defmodule TestHelper do
  def bypass(context) do
    {:ok, pid} =
      Bandit.start_link(
        plug: context.bypass || raise("bypass callback missing"),
        port: 0
      )

    {:ok, {_ip, port}} = ThousandIsland.listener_info(pid)
    %{port: port}
  end
end

Logger.configure(level: :error)
windows_exclude = if match?({:win32, _}, :os.type()), do: [:unix], else: []
ExUnit.start(exclude: windows_exclude)
