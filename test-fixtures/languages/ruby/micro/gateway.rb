require_relative 'user_service'
require 'sinatra'

class Gateway < Sinatra::Base
  # A real Sinatra class-mode entry point keeps the compiler proof honest:
  # `params` is the framework-owned implicit receiver, not an arbitrary helper
  # parameter that happens to use the conventional spelling.
  def handle_request
    token = params['token']    # source: user input
    action = params['action']  # source: user input

    user = UserService.get_user(token)              # flows to SQL injection
    result = UserService.update_user(token, action) # flows to command injection

    { user: user, result: result }
  end

  get '/api/user' do
    content_type :json
    handle_request.to_json
  end
end
