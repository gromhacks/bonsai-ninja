%% Assignment-chain audit fixture (Erlang).
%% Uses os:getenv/1 as source (erlang.source.os_getenv) + os:cmd/1 as
%% cmdi sink. The maps:get/2 subscript shape is a separate adapter
%% audit (Task #265).
-module(app).
-export([
    chain_simple/0, chain_multi_hop/0, chain_branch_join/1,
    chain_loop_carried/1, chain_clean_constant/0, chain_cross_file/0
]).

-define(CONST_OK, "ls /tmp").

passthrough(X) -> X.
wrap(X) -> "wrapped:" ++ X.
combine(Acc, Item) -> Acc ++ ":" ++ Item.

chain_simple() ->
    %% POSITIVE
    Tmp = os:getenv("CMD1"),
    os:cmd(Tmp).

chain_multi_hop() ->
    %% POSITIVE
    T1 = os:getenv("CMD2"),
    T2 = passthrough(T1),
    T3 = wrap(T2),
    T4 = passthrough(T3),
    os:cmd(T4).

chain_branch_join(Cond) ->
    %% POSITIVE
    T = case Cond of
            true -> os:getenv("CMD3");
            false -> "safe-static"
        end,
    os:cmd(T).

chain_loop_carried(Items) ->
    %% POSITIVE
    Acc0 = os:getenv("CMD4"),
    Acc = lists:foldl(fun(I, A) -> combine(A, I) end, Acc0, Items),
    os:cmd(Acc).

chain_clean_constant() ->
    %% NEGATIVE
    _Unused = os:getenv("IGNORED"),
    os:cmd(?CONST_OK).

chain_cross_file() ->
    %% POSITIVE
    T = os:getenv("CMD9"),
    executor:run_in_other_file(T).
