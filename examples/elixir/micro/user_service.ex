defmodule MyApp.UserService do
  alias MyApp.AuthService

  def get_user(token) do
    AuthService.verify_token(token)
  end

  def update_user(token, action) do
    user_id = AuthService.verify_token(token)

    if user_id do
      AuthService.run_admin_command(user_id, action)
    end

    user_id
  end
end
