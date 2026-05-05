defmodule App do
    def tainted_through_try do
        t = try do
            System.get_env("CMD")
        rescue
            _ -> ""
        end
        System.cmd("sh", ["-c", t])
    end
end
