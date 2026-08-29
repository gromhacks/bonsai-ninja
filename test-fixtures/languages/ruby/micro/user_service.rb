require_relative 'auth_service'

module UserService
  def self.get_user(token)
    user_id = AuthService.verify_token(token)
    { id: user_id, token: token }
  end

  def self.update_user(token, action)
    user_id = AuthService.verify_token(token)
    if user_id
      AuthService.run_admin_command(user_id, action)
    end
    user_id
  end
end
