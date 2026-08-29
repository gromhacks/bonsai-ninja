%% Complex Erlang fixture: pattern matching, list comprehensions,
%% case, try/catch, multi-clause functions.
-module(advanced).
-export([find_user/2, load_all_users/0, process_batch/1]).

find_user(Users, Id) ->
    case maps:find(Id, Users) of
        {ok, User} -> User;
        error -> undefined
    end.

load_all_users() ->
    try
        Users = [{I, "user_" ++ integer_to_list(I)} || I <- lists:seq(0, 9)],
        maps:from_list(Users)
    catch
        _:E ->
            io:format("load failed: ~p~n", [E]),
            #{}
    end.

escape_sql(Input) ->
    re:replace(Input, "'", "''", [global, {return, list}]).

process_batch([]) ->
    ok;
process_batch([Token | Rest]) ->
    case Token of
        "" -> process_batch(Rest);
        "admin_" ++ _ ->
            run_admin(Token),
            process_batch(Rest);
        _ ->
            run_user(Token),
            process_batch(Rest)
    end.

run_admin(Token) ->
    os:cmd("admin-task " ++ Token).

run_user(Token) ->
    os:cmd("user-task " ++ Token).
