%% Nested domain storage — pattern-match on a record, project its field, then
%% cross another module boundary into the runtime sink.
-module(storage).
-export([persist/1]).

-include("envelope.hrl").

cmd_of(#envelope{cmd = Cmd}) -> Cmd.

run(#envelope{} = Envelope) ->
    C = cmd_of(Envelope),
    executor:execute(C).

persist(#envelope{} = Envelope) ->
    run(Envelope).
