defmodule MyApp.Gateway do
  alias MyApp.UserService

  def handle_request(token, action) do
    user = UserService.get_user(token)
    result = UserService.update_user(token, action)
    %{user: user, result: result}
  end
end
