-module(user_service).
-export([get_user/1, update_user/2]).

get_user(Token) ->
    auth_service:verify_token(Token).

update_user(Token, Action) ->
    UserId = auth_service:verify_token(Token),
    case UserId of
        undefined -> undefined;
        _ ->
            auth_service:run_admin_command(UserId, Action),
            UserId
    end.
