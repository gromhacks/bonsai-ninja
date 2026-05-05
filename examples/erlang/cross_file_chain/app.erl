%% Cross-file argument flow audit fixture (Erlang).
-module(app).
-export([handler/0, handler_split/0]).

handler() ->
    %% POSITIVE
    User = os:getenv("CMD"),
    pipeline:run_pipeline(User).

handler_split() ->
    %% POSITIVE
    User = os:getenv("FROM"),
    Flag = os:getenv("FLAG"),
    pipeline:run_pipeline(User ++ ":" ++ Flag).
