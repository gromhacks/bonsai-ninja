-module(app).
-export([executor/1, run_cb/2, pass_to_callback/0]).

executor(Cmd) ->
    os:cmd(Cmd).

run_cb(Cb, Value) ->
    Cb(Value).

pass_to_callback() ->
    T = os:getenv("CMD"),
    run_cb(fun executor/1, T).
