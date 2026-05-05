%% mega_flow Erlang entry — io:get_line is the SOURCE, threaded
%% through a pipeline that exercises every idiomatic Erlang flow
%% construct (pattern matching, guards, list comprehensions, records,
%% case/receive, try/catch, anonymous funs).
-module(app).
-export([main/1, handle_request/0]).

-include("envelope.hrl").

main(_Args) ->
    handle_request().

handle_request() ->
    %% SOURCE — io:get_line reads one tainted line from stdin.
    Raw = io:get_line(""),
    User = case os:getenv("USER") of false -> "anon"; V -> V end,

    Envelope = #envelope{
        kind = run,
        cmd = Raw,
        user = User,
        length = length(Raw),
        extras = [Raw]
    },

    pipeline:orchestrate(Envelope).
