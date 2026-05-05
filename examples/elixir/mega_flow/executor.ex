defmodule Mega.Executor do
  # SINK — :os.cmd · elixir.cmdi.os_cmd · CWE-78
  def execute(cmd) do
    :os.cmd(String.to_charlist(cmd))
    cmd
  end

  def clean_twin do
    # NEGATIVE — same sink kind with a constant argument must not report.
    :os.cmd(~c"echo clean")
    "clean"
  end
end
