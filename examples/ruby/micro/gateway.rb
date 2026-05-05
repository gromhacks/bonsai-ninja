require_relative 'user_service'
require 'sinatra'

# Named entry point so cross-module flow enumeration has a captured
# decl to anchor chains on. Sinatra's `get '/api/user' do ... end`
# block is a DSL construct, not a `def`, so tree-sitter doesn't
# surface it as a function decl and it can't serve as a chain
# root — callers that want entry → ... → sink flows (the canonical
# `handle_request → update_user → verify_token` shape other
# languages ship) need a real method here.
def handle_request(params)
  token = params['token']    # source: user input
  action = params['action']  # source: user input

  user = UserService.get_user(token)         # flows to SQL injection
  result = UserService.update_user(token, action) # flows to command injection

  { user: user, result: result }
end

get '/api/user' do
  content_type :json
  handle_request(params).to_json
end
