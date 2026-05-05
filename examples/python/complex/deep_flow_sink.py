"""
Deep cross-file flow chain: Plugin executor (contains dangerous sinks).

Receives processed command strings and executes them via os.system.
The taint chain terminates here.
"""

import os
import subprocess


class DfcPluginExecutor:
    """Executes plugin commands after final preparation."""

    def __init__(self, handler_name):
        # Step 25 (from caller): store handler name
        self.handler_name = handler_name
        self.config = DfcExecutionConfig()

    def prepare_and_run(self, exec_string, metadata):
        """Prepare the final command and execute it."""
        # Step 27: build the shell prefix
        shell_prefix = self.config.get_prefix()
        # Step 28: combine handler name into command
        handler_cmd = self.handler_name + " " + exec_string
        # Step 29: apply any metadata-based transformations
        if metadata.get("transformed"):
            handler_cmd = handler_cmd + " --transformed"
        # Step 30: wrap in shell invocation
        full_shell_cmd = shell_prefix + " -c '" + handler_cmd + "'"
        # Step 31: pass to the runner
        runner = DfcCommandRunner()
        result = runner.execute(full_shell_cmd)
        return result

    def prepare_batch(self, commands, metadata):
        """Execute multiple commands in sequence."""
        results = []
        for cmd in commands:
            combined = self.handler_name + " " + cmd
            if metadata.get("origin") == "cli":
                combined = combined + " --interactive"
            runner = DfcCommandRunner()
            res = runner.execute(combined)
            results.append(res)
        return results


class DfcExecutionConfig:
    """Configuration for command execution environment."""

    def __init__(self):
        self.shell = "/bin/bash"
        self.timeout = 30
        self.env_vars = {}

    def get_prefix(self):
        # Step 27: returns the shell path used as command prefix
        prefix = self.shell
        return prefix

    def set_timeout(self, seconds):
        self.timeout = seconds


class DfcCommandRunner:
    """Actually runs shell commands (contains the SINK)."""

    def __init__(self):
        self.last_exit_code = None
        self.last_output = ""

    def execute(self, command_string):
        """Execute a command string via the system shell."""
        # Step 32: log the command
        log_entry = "Executing: " + command_string
        print(log_entry)
        # Step 33: format for execution
        formatted = command_string.strip()
        # Step 34: final variable before sink
        final_cmd = formatted
        # Step 35: SINK -- tainted data reaches os.system
        self.last_exit_code = os.system(final_cmd)
        self.last_output = "exit:" + str(self.last_exit_code)
        return self.last_output

    def execute_subprocess(self, command_string):
        """Alternative execution path using subprocess."""
        parts = command_string.split()
        result = subprocess.run(parts, capture_output=True, text=True)
        return result.stdout
