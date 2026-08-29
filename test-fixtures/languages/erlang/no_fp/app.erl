-module(app).
-export([decoy/0, unrelated_chain/0]).

decoy() ->
    _Unused = os:getenv("IGNORED"),
    os:cmd("ls /tmp").

unrelated_chain() ->
    string:to_upper("hello").
