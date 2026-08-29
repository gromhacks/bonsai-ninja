defmodule LanguageGauntlet.App do
  use LanguageGauntlet.Web, :controller

  # language_gauntlet Elixir entry — Phoenix action params are the SOURCE, threaded
  # through a pipeline that exercises every idiomatic Elixir flow
  # construct (pattern matching, guards, pipe operator, with-clause,
  # case/cond, comprehensions, try/rescue, structs).

  defmodule Envelope do
    defstruct kind: :run, cmd: "", user: "anon", length: 0, extras: []
  end

  def main do
    handle(nil, %{})
  end

  # SOURCE — the second parameter of a Phoenix controller action.
  def handle(_conn, params) do
    raw = Map.get(params, "cmd", "")
    user = Map.get(params, "user", "remote")

    envelope = %Envelope{
      kind: :run,
      cmd: "#{raw}",
      user: user,
      length: String.length(raw),
      extras: [raw],
    }

    LanguageGauntlet.Pipeline.orchestrate(envelope)
  end
end
