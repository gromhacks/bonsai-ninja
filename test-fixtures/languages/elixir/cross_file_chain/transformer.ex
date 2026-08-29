defmodule Transformer do
  def transform_and_forward(value) do
    upper = String.upcase(value)
    Executor.execute(upper)
  end
end
