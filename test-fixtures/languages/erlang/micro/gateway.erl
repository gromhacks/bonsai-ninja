-module(gateway).
-export([handle_request/2]).

handle_request(Token, Action) ->
    User = user_service:get_user(Token),
    Result = user_service:update_user(Token, Action),
    {User, Result}.
