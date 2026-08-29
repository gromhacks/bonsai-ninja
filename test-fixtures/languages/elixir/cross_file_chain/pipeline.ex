defmodule Pipeline do
  def run_pipeline(payload) do
    wrapped = "[" <> payload <> "]"
    Transformer.transform_and_forward(wrapped)
  end
end
