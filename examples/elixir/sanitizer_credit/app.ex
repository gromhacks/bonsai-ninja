defmodule App do
    def unsanitized do
        t = System.get_env("CMD")
        System.cmd("sh", ["-c", t])
    end
    def sanitized do
        t = System.get_env("CMD")
        # Argv-form System.cmd with explicit args is the safe pattern.
        System.cmd("echo", [t])
    end
end
