-module(app).
-export([direct/1, qualified/1]).
direct(Req) ->
    {ok, Body, _} = cowboy_req:read_body(Req),
    binary_to_term(Body).
qualified(Req) ->
    {ok, Body, _} = cowboy_req:read_body(Req),
    erlang:binary_to_term(Body).
