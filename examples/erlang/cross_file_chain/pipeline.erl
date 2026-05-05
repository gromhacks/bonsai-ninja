-module(pipeline).
-export([run_pipeline/1]).

run_pipeline(Payload) ->
    Wrapped = "[" ++ Payload ++ "]",
    transformer:transform_and_forward(Wrapped).
