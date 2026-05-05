"""
Deep cross-file flow chain: Middleware and helper classes.

Provides DfcRequestContext, DfcMiddlewareChain, and DfcCommandRegistry used by
the main pipeline. Data flows through middleware transformations before
being passed to the executor.
"""


class DfcRequestContext:
    """Carries command data through the middleware pipeline."""

    def __init__(self, command, params):
        # Step 12 (from caller): store command and params
        self.command = command
        self.params = params
        self.metadata = {}
        self.trace_log = []

    def append_trace(self, entry):
        self.trace_log.append(entry)

    def get_full_payload(self):
        """Returns combined command + params for downstream use."""
        payload = self.command + " --args " + self.params
        return payload


class DfcMiddlewareChain:
    """Processes a DfcRequestContext through a series of middleware functions."""

    def __init__(self):
        self.middlewares = []

    def add_logging_middleware(self):
        def logging_mw(ctx):
            # Step 17: read command from context
            logged_cmd = ctx.command
            ctx.append_trace("LOG: " + logged_cmd)
            return ctx
        self.middlewares.append(logging_mw)

    def add_transform_middleware(self):
        def transform_mw(ctx):
            # Step 18: read params from context
            raw_params = ctx.params
            # Step 19: transform params (format for shell)
            transformed = raw_params.replace(",", " ")
            # Step 20: write back to context
            ctx.params = transformed
            # Step 21: update metadata with transform record
            ctx.metadata["transformed"] = True
            ctx.metadata["original_params"] = raw_params
            return ctx
        self.middlewares.append(transform_mw)

    def process(self, ctx):
        """Run all middleware in order, returning the modified context."""
        current = ctx
        for mw in self.middlewares:
            # Step 16-21: each middleware reads and modifies the context
            current = mw(current)
        return current


class DfcCommandRegistry:
    """Registry of available plugin command handlers."""

    def __init__(self):
        self._handlers = {
            "deploy": "dfc_deploy_handler",
            "backup": "dfc_backup_handler",
            "migrate": "dfc_migrate_handler",
            "shell": "dfc_shell_handler",
        }

    def get_handler(self, plugin_name):
        """Look up handler by plugin name."""
        # Step 24 (from caller): resolve plugin name to handler
        if plugin_name in self._handlers:
            handler = self._handlers[plugin_name]
            return handler
        # Fallback: use the plugin name itself as the handler
        fallback = plugin_name + "_handler"
        return fallback

    def list_plugins(self):
        return list(self._handlers.keys())


class DfcConfigLoader:
    """Loads configuration that affects command execution."""

    def __init__(self, config_path=None):
        self.config_path = config_path or "/etc/plugins.conf"
        self.settings = {}

    def load(self):
        self.settings = {
            "timeout": 30,
            "shell": "/bin/bash",
            "allow_exec": True,
        }
        return self.settings

    def get_shell(self):
        if "shell" not in self.settings:
            self.load()
        shell_path = self.settings["shell"]
        return shell_path
