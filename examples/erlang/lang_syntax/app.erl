%% Language-specific syntax audit (Erlang).
%% Tests Erlang-special forms:
%%   - <<...>> bit-string concat: << "prefix", X/binary, "suffix" >>
%%   - list-comprehension: [X || X <- L]
-module(app).
-export([handle_bitstring/0, handle_concat/0]).

handle_bitstring() ->
    %% POSITIVE: bit-string concat with tainted X carries taint into Out.
    Tainted = os:getenv("CMD"),
    X = list_to_binary(Tainted),
    Out = <<"prefix:", X/binary, ":suffix">>,
    os:cmd(binary_to_list(Out)).

handle_concat() ->
    %% POSITIVE: list-concat (++) propagates taint into the result.
    Tainted = os:getenv("CMD"),
    Out = "prefix:" ++ Tainted ++ ":suffix",
    os:cmd(Out).
