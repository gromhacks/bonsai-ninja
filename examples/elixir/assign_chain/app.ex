# Assignment-chain audit fixture (Elixir).
defmodule App do
  @const_ok "ls /tmp"

  def passthrough(x), do: x
  def wrap(x), do: "wrapped:" <> x
  def combine(acc, item), do: acc <> ":" <> item

  def chain_simple(params) do
    # POSITIVE
    tmp = params["c1"]
    System.cmd("sh", ["-c", tmp])
  end

  def chain_multi_hop(params) do
    # POSITIVE
    t1 = params["c2"]
    t2 = passthrough(t1)
    t3 = wrap(t2)
    t4 = passthrough(t3)
    System.cmd("sh", ["-c", t4])
  end

  def chain_branch_join(params, cond) do
    # POSITIVE
    t =
      if cond do
        params["c3"]
      else
        "safe-static"
      end

    System.cmd("sh", ["-c", t])
  end

  def chain_loop_carried(params, items) do
    # POSITIVE
    acc = params["c4"]
    final = Enum.reduce(items, acc, fn item, a -> combine(a, item) end)
    System.cmd("sh", ["-c", final])
  end

  def chain_subscript_write(params) do
    # POSITIVE
    cmds = %{}
    cmds = Map.put(cmds, "x", params["c6"])
    System.cmd("sh", ["-c", cmds["x"]])
  end

  def chain_clean_constant(params) do
    # NEGATIVE
    _unused = params["ignored"]
    System.cmd("sh", ["-c", @const_ok])
  end

  def chain_cross_file(params) do
    # POSITIVE
    t = params["c9"]
    Executor.run_in_other_file(t)
  end
end
