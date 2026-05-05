defmodule MyApp.Advanced do
  @moduledoc """
  Complex Elixir fixture exercising pattern matching, pipes, try/rescue,
  case, for comprehensions.
  """

  def find_user(users, id) do
    case Map.get(users, id) do
      nil -> nil
      user -> user
    end
  end

  def load_all_users do
    try do
      for i <- 0..9, into: %{} do
        {i, "user_#{i}"}
      end
    rescue
      e ->
        IO.puts("load failed: #{inspect(e)}")
        %{}
    end
  end

  def escape_sql(input) do
    String.replace(input, "'", "''")
  end

  def dispatch_token(token) do
    cond do
      token == "" -> :skip
      String.starts_with?(token, "admin_") -> run_admin(token)
      true -> run_user(token)
    end
  end

  def process_batch(tokens) do
    Enum.each(tokens, fn token -> dispatch_token(token) end)
  end

  def run_admin(token) do
    System.cmd("sh", ["-c", "admin-task " <> token])
  end

  def run_user(token) do
    System.cmd("sh", ["-c", "user-task " <> token])
  end
end
