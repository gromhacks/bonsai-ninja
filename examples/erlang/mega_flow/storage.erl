%% Storage — pattern-match on record, accessor fn, procedural
%% dispatch to the sink.
-module(storage).
-export([persist/1]).

-include("envelope.hrl").

cmd_of(#envelope{cmd = Cmd}) -> Cmd.

run(#envelope{} = Envelope) ->
    C = cmd_of(Envelope),
    executor:execute(C).

persist(#envelope{} = Envelope) ->
    run(Envelope).
