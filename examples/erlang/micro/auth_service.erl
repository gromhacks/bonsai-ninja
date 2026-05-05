-module(auth_service).
-export([verify_token/1, run_admin_command/2]).

verify_token(Token) ->
    Query = ["SELECT user_id FROM tokens WHERE token = '", Token, "'"],
    %% sink: SQL injection via iolist concat
    io:format("~s~n", [Query]),
    1.

run_admin_command(UserId, Action) ->
    case UserId of
        undefined -> ok;
        _ ->
            %% sink: command injection via os:cmd
            os:cmd("notify-admin " ++ Action),
            ok
    end.
