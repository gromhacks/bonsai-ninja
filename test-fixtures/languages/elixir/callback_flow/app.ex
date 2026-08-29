defmodule App do
    def executor(cmd) do
        System.cmd("sh", ["-c", cmd])
    end
    def run_cb(cb, value) do
        cb.(value)
    end
    def pass_to_callback do
        t = System.get_env("CMD")
        run_cb(&executor/1, t)
    end
end
