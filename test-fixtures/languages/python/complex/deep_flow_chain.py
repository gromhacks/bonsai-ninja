"""
Deep cross-file flow chain: Plugin command executor pipeline.

User input flows through ~35 steps across 3 files, 4+ functions, 2+ classes,
crossing variable assignments, method calls, constructors, dict access,
string concatenation, conditionals, and loops before reaching a dangerous sink.

Flow: input() -> parse -> validate -> transform -> format -> execute (os.system)
"""

import os
from deep_flow_helpers import DfcCommandRegistry, DfcRequestContext, DfcMiddlewareChain
from deep_flow_sink import DfcPluginExecutor


def dfc_audited(func):
    return func


class DfcCommandParser:
    """Parses raw user input into structured command objects."""

    def __init__(self, delimiter="::"):
        self.delimiter = delimiter
        self.raw_buffer = ""

    def read_input(self):
        # Step 1: user input (SOURCE)
        raw_text = input("Enter plugin command: ")
        # Step 2: store in instance field
        self.raw_buffer = raw_text
        return self.raw_buffer

    def tokenize(self, text):
        # Step 3: split into parts
        parts = text.strip().split(self.delimiter)
        # Step 4: build token dict
        tokens = {
            "plugin_name": parts[0] if len(parts) > 0 else "",
            "action": parts[1] if len(parts) > 1 else "default",
            "arguments": self.delimiter.join(parts[2:]) if len(parts) > 2 else "",
        }
        return tokens

    def normalize(self, tokens):
        # Step 5: normalize plugin name
        plugin_id = tokens["plugin_name"].lower().replace("-", "_")
        # Step 6: build normalized command string
        normalized_action = tokens["action"].strip()
        # Step 7: combine into command descriptor
        descriptor = {
            "id": plugin_id,
            "action": normalized_action,
            "args": tokens["arguments"],
            "full_command": plugin_id + "." + normalized_action,
        }
        return descriptor


class DfcInputValidator:
    """Validates parsed command descriptors."""

    ALLOWED_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789_.-/ ")

    def __init__(self):
        self.errors = []

    def check_format(self, descriptor):
        # Step 8: extract command string from descriptor
        cmd_str = descriptor["full_command"]
        # Step 9: extract arguments
        cmd_args = descriptor["args"]
        # Step 10: build validated payload (no actual sanitization -- vulnerable)
        if len(cmd_str) > 0:
            validated = {
                "command": cmd_str,
                "parameters": cmd_args,
                "is_valid": True,
            }
        else:
            validated = {
                "command": cmd_str,
                "parameters": cmd_args,
                "is_valid": False,
            }
        return validated


def dfc_build_request(validated_payload):
    """Wraps validated payload into a DfcRequestContext for middleware processing."""
    # Step 11: extract fields
    command = validated_payload["command"]
    params = validated_payload["parameters"]
    # Step 12: create context object (cross-file, into deep_flow_helpers)
    ctx = DfcRequestContext(command=command, params=params)
    # Step 13: attach metadata
    ctx.metadata["origin"] = "cli"
    ctx.metadata["validated"] = validated_payload["is_valid"]
    return ctx


def dfc_apply_middleware(ctx):
    """Runs the middleware chain on the request context."""
    # Step 14: create middleware chain (cross-file)
    chain = DfcMiddlewareChain()
    # Step 15: register built-in middleware
    chain.add_logging_middleware()
    chain.add_transform_middleware()
    # Step 16: process through chain
    processed_ctx = chain.process(ctx)
    return processed_ctx


def dfc_dispatch_to_executor(processed_ctx):
    """Looks up the plugin and dispatches the command for execution."""
    # Step 22 (after middleware): extract processed command
    final_command = processed_ctx.command
    final_params = processed_ctx.params
    # Step 23: build execution string
    exec_string = final_command + " " + final_params
    # Step 24: create registry and look up plugin
    registry = DfcCommandRegistry()
    plugin_name = final_command.split(".")[0]
    handler = registry.get_handler(plugin_name)
    # Step 25: if handler found, wrap in executor (cross-file, into deep_flow_sink)
    if handler is not None:
        executor = DfcPluginExecutor(handler_name=handler)
        # Step 26: pass to executor for final processing
        result = executor.prepare_and_run(exec_string, processed_ctx.metadata)
        return result
    return None


@dfc_audited
def dfc_main():
    parser = DfcCommandParser()
    validator = DfcInputValidator()

    # Steps 1-2: read input
    raw = parser.read_input()
    # Steps 3-4: tokenize
    tokens = parser.tokenize(raw)
    # Steps 5-7: normalize
    descriptor = parser.normalize(tokens)
    # Steps 8-10: validate
    validated = validator.check_format(descriptor)
    # Steps 11-13: build request context
    ctx = dfc_build_request(validated)
    # Steps 14-21: apply middleware
    processed = dfc_apply_middleware(ctx)
    # Steps 22-35: dispatch and execute
    result = dfc_dispatch_to_executor(processed)

    if result is not None:
        print("Execution result: " + str(result))


if __name__ == "__main__":
    dfc_main()
