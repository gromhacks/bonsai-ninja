-module(app).
-export([taint_one_leg/1, taint_overwritten/1]).

taint_one_leg(Cond) ->
    X = case Cond of
            true -> os:getenv("CMD");
            false -> "safe-static"
        end,
    os:cmd(X).

taint_overwritten(Cond) ->
    _X0 = os:getenv("CMD"),
    X = case Cond of
            true -> "clean-then";
            false -> "clean-else"
        end,
    os:cmd(X).
