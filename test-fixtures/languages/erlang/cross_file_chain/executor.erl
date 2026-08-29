-module(executor).
-export([execute/1]).

execute(Cmd) ->
    %% POSITIVE (terminal cross-file sink)
    os:cmd(Cmd).
