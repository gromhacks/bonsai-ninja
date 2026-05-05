defmodule Executor do
  def run_in_other_file(cmd) do
    # POSITIVE (cross-file)
    System.cmd("sh", ["-c", cmd])
  end
end
