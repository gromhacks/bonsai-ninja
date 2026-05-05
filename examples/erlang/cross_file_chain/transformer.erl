-module(transformer).
-export([transform_and_forward/1]).

transform_and_forward(Value) ->
    Upper = string:to_upper(Value),
    executor:execute(Upper).
