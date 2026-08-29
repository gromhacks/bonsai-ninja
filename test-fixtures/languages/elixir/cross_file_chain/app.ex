# Cross-file argument flow audit fixture (Elixir).
defmodule App do
  def handler do
    # POSITIVE
    user = System.get_env("CMD")
    Pipeline.run_pipeline(user)
  end

  def handler_split do
    # POSITIVE
    user = System.get_env("FROM")
    flag = System.get_env("FLAG")
    Pipeline.run_pipeline("#{user}:#{flag}")
  end
end
