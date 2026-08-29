defmodule App do
    def taint_one_leg(cond) do
        x = if cond, do: System.get_env("CMD"), else: "safe-static"
        System.cmd("sh", ["-c", x])
    end
    def taint_overwritten(cond) do
        _x0 = System.get_env("CMD")
        x = if cond, do: "clean-then", else: "clean-else"
        System.cmd("sh", ["-c", x])
    end
end
