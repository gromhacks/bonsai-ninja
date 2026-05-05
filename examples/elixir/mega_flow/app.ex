defmodule Mega.App do
  # mega_flow Elixir entry — System.argv is the SOURCE, threaded
  # through a pipeline that exercises every idiomatic Elixir flow
  # construct (pattern matching, guards, pipe operator, with-clause,
  # case/cond, comprehensions, try/rescue, structs).

  defmodule Envelope do
    defstruct kind: :run, cmd: "", user: "anon", length: 0, extras: []
  end

  # SOURCE — System.argv (CLI input).
  def main do
    [raw | rest] = System.argv()
    user = List.first(rest) || "anon"

    envelope = %Envelope{
      kind: :run,
      cmd: "#{raw}",
      user: user,
      length: String.length(raw),
      extras: [raw],
    }

    Mega.Pipeline.orchestrate(envelope)
  end
end
