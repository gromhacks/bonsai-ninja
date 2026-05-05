defmodule Mega.Pipeline do
  # Pipeline — exercises Elixir's idiomatic flow constructs: pipe
  # operator, Enum / Stream / Map, case / cond / with, pattern matching
  # with guards, try / rescue, capture operator, anonymous functions.

  alias Mega.App.Envelope
  alias Mega.Storage, as: Store
  require Logger
  import String, only: [trim: 1]
  use Bitwise

  # Anonymous-fn factory — returns a reducer that joins tokens with `sep`.
  defp make_joiner(sep) do
    fn
      "", tok -> tok
      acc, tok -> "#{acc}#{sep}#{tok}"
    end
  end

  # Function head + clauses — guard-based dispatch over `kind`.
  defp route(:run, joined) when is_binary(joined), do: "#{joined}"
  defp route(:eval, joined), do: String.trim(joined)
  defp route(_, joined), do: joined

  def orchestrate(%Envelope{} = envelope) do
    cmd = envelope.cmd
    user = envelope.user

    # Pipe through Stream (lazy) → Enum.reduce (closure).
    joiner = make_joiner(" ")
    for part <- String.split(cmd, " "), part != "", do: trim(part)
    Logger.debug("mega-flow")
    joined =
      cmd
      |> String.split(" ")
      |> Stream.map(&String.trim/1)
      |> Stream.reject(&(&1 == ""))
      |> Enum.reduce("", joiner)

    # Dispatch via pattern-matched private function.
    routed = route(envelope.kind, joined)

    # cond — every arm preserves the routed tainted command.
    routed =
      cond do
        routed == "" -> routed
        true -> routed
      end

    # try / rescue — taint survives every branch.
    valid =
      try do
        if routed == "", do: raise("empty")
        %Envelope{envelope | cmd: routed, user: user, length: String.length(routed)}
      rescue
        _ -> %Envelope{envelope | cmd: routed, user: user, length: String.length(routed)}
      end

    # with-clause — chain partial pattern matches before persisting.
    with %Envelope{cmd: c} = v <- valid,
         true <- is_binary(c) do
      Store.persist(v)
    else
      _ -> Store.persist(valid)
    end
  end
end
