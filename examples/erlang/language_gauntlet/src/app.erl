%% language_gauntlet Erlang entry — a Cowboy request query is the SOURCE, threaded
%% through a pipeline that exercises every idiomatic Erlang flow
%% construct (pattern matching, guards, list comprehensions, records,
%% case/receive, try/catch, anonymous funs).
-module(app).
-export([main/1, handle_request/1]).

-include("envelope.hrl").

main(_Args) ->
    handle_request(undefined).

handle_request(Req) ->
    %% SOURCE — Cowboy exposes the remote HTTP query string.
    Raw = cowboy_req:qs(Req),
    User = "remote",

    Envelope = #envelope{
        kind = run,
        cmd = Raw,
        user = User,
        length = length(Raw),
        extras = [Raw]
    },

    pipeline:orchestrate(Envelope).
