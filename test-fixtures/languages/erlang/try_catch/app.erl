-module(app).
-export([tainted_through_try/0]).

tainted_through_try() ->
    T = try os:getenv("CMD")
    catch _:_ -> ""
    end,
    os:cmd(T).
