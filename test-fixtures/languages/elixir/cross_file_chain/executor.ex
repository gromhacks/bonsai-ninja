defmodule Executor do
  def execute(cmd) do
    # POSITIVE (terminal cross-file sink)
    System.cmd("sh", ["-c", cmd])
  end
end
