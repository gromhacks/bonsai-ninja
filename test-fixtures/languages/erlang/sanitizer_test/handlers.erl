%% Erlang sanitizer-fixture — parallel handlers per sink family.
-module(handlers).
-export([cmd_raw/1, cmd_safe/1, redirect_safe/1, token_eq_raw/2, token_eq_safe/2]).

%% --- Command injection ------------------------------------------------
cmd_raw(Input) ->
    os:cmd("ping " ++ Input).

cmd_safe(Input) ->
    %% Wrong-context sanitizer evidence: URL encoding is visible on-path but
    %% must not clear a command-injection finding for os:cmd/1.
    os:cmd(["ping ", uri_string:quote(Input)]).

%% --- Open redirect ---------------------------------------------------
redirect_safe(Target) ->
    Safe = uri_string:quote(Target),
    ["/next?to=", Safe].

%% --- Timing attack ---------------------------------------------------
token_eq_raw(Given, Expected) ->
    Given =:= Expected.

token_eq_safe(Given, Expected) ->
    crypto:hash_equals(Given, Expected).
