# Language-specific syntax audit (Elixir).
# Tests Elixir-special forms:
#   - <> string-concat operator
#   - string interpolation "#{expr}"
defmodule App do
  def handle_concat do
    # POSITIVE: <> propagates taint.
    tainted = System.get_env("CMD")
    out = "prefix:" <> tainted <> ":suffix"
    System.cmd("sh", ["-c", out])
  end

  def handle_interp do
    # POSITIVE: string interpolation propagates taint.
    tainted = System.get_env("CMD")
    out = "prefix:#{tainted}:suffix"
    System.cmd("sh", ["-c", out])
  end
end
