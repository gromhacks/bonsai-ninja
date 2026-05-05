-module(app).
-export([unsanitized/0, sanitized/0]).

unsanitized() ->
    T = os:getenv("CMD"),
    os:cmd(T).

sanitized() ->
    T = os:getenv("CMD"),
    Safe = re:replace(T, "[^A-Za-z0-9_-]", "", [global, {return, list}]),
    os:cmd("echo " ++ Safe).
