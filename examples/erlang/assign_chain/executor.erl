-module(executor).
-export([run_in_other_file/1]).

run_in_other_file(Cmd) ->
    %% POSITIVE (cross-file)
    os:cmd(Cmd).
