%% Pipeline — exercises Erlang's idiomatic flow constructs: list
%% comprehensions, lists:map / filter / foldl, case expressions,
%% guards, try / catch, anonymous funs, pattern matching on records.
-module(pipeline).
-export([orchestrate/1]).
-import(storage, [persist/1]).

-include("envelope.hrl").

%% Closure factory — returns an anonymous fun reducer that joins tokens.
make_joiner(Sep) ->
    fun("", Tok) -> Tok;
       (Acc, Tok) -> Acc ++ Sep ++ Tok
    end.

%% Function-clause + guard dispatch over `Kind`.
route(run, Joined) when is_list(Joined) -> Joined;
route(eval, Joined) -> string:strip(Joined);
route(_, Joined) -> Joined.

orchestrate(#envelope{} = Envelope) ->
    Cmd = Envelope#envelope.cmd,
    User = Envelope#envelope.user,

    %% Tokens via list comprehension, lists:map, and lists:filter —
    %% taint rides each element through every collection transform.
    RawTokens = [Part || Part <- string:tokens(Cmd, " ")],
    Stripped = lists:map(fun string:strip/1, RawTokens),
    Tokens = lists:filter(fun(Part) -> Part =/= "" end, Stripped),

    %% lists:foldl + anonymous-fun reducer — taint rides the accumulator.
    Joiner = make_joiner(" "),
    Joined = lists:foldl(
        fun(Tok, Acc) -> Joiner(Acc, Tok) end,
        "",
        Tokens),

    %% Case expression routing.
    Routed = route(Envelope#envelope.kind, Joined),
    receive
        _Msg -> ok
    after 0 ->
        ok
    end,

    %% try / catch — taint survives every branch.
    Valid = try
        case Routed of
            "" -> throw(empty);
            _ -> Envelope#envelope{cmd = Routed, user = User, length = length(Routed)}
        end
    catch
        _:_ -> Envelope#envelope{cmd = Routed, user = User, length = length(Routed)}
    end,

    persist(Valid).
