defmodule LanguageGauntlet.Contracts.CommandRunner do
  @moduledoc false

  @callback execute(String.t()) :: String.t()
end
