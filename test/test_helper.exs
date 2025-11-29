Logger.configure(level: :info)
windows_exclude = if match?({:win32, _}, :os.type()), do: [:unix], else: []
ExUnit.start(exclude: windows_exclude)
