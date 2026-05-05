%% Receiver-type audit fixture (Erlang). Module-call form.
-module(app).
-export([handle/0]).

handle() ->
    %% POSITIVE
    Tainted = os:getenv("CMD"),
    os:cmd(Tainted).
