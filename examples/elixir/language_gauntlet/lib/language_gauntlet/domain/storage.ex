defmodule LanguageGauntlet.Storage do
  # Storage — uses behaviour + protocol-style dispatch to thread the
  # tainted cmd from the envelope to the executor.

  alias LanguageGauntlet.App.Envelope

  # Behaviour-style callback (a protocol could fit too).
  defp cmd_of(%Envelope{cmd: cmd}), do: cmd

  defp run(%Envelope{} = envelope) do
    c = cmd_of(envelope)
    LanguageGauntlet.Executor.execute(c)
  end

  def persist(%Envelope{} = envelope) do
    run(envelope)
  end
end
