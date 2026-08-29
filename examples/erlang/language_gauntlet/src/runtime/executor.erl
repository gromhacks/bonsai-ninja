-module(executor).
-export([execute/1, clean_twin/0]).

execute(Cmd) ->
    %% SINK — os:cmd · erlang.cmdi.os_cmd · CWE-78
    os:cmd(Cmd),
    Cmd.

clean_twin() ->
    %% NEGATIVE — same sink kind with a constant argument must not report.
    os:cmd("echo clean"),
    "clean".
