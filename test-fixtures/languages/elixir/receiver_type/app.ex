# Receiver-type audit fixture (Elixir).
# System.cmd — module-namespace call.
defmodule App do
  def handle do
    # POSITIVE
    tainted = System.get_env("CMD")
    System.cmd("sh", ["-c", tainted])
  end
end
