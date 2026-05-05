defmodule MyApp.AuthService do
  def verify_token(token) do
    query = "SELECT user_id FROM tokens WHERE token = '" <> token <> "'"
    # sink: SQL injection via concatenation
    IO.puts(query)
    1
  end

  def run_admin_command(user_id, action) do
    if user_id do
      # sink: command injection via shell concatenation
      System.cmd("sh", ["-c", "notify-admin " <> action])
    end
  end
end
