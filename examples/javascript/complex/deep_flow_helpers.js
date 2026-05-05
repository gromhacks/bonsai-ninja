/**
 * Deep cross-file flow chain: Middleware and helper classes.
 *
 * Provides DfcRequestContext, DfcMiddlewareChain, and DfcCommandRegistry used by
 * the main pipeline. Data flows through middleware transformations before
 * being passed to the executor.
 */

class DfcRequestContext {
  // Step 12 (from caller): store command and params
  constructor(command, params) {
    this.command = command;
    this.params = params;
    this.metadata = {};
    this.traceLog = [];
  }

  appendTrace(entry) {
    this.traceLog.push(entry);
  }

  getFullPayload() {
    const payload = this.command + " --args " + this.params;
    return payload;
  }
}

class DfcMiddlewareChain {
  constructor() {
    this.middlewares = [];
  }

  addLoggingMiddleware() {
    const loggingMW = function (ctx) {
      // Step 17: read command from context
      const loggedCmd = ctx.command;
      ctx.appendTrace("LOG: " + loggedCmd);
      return ctx;
    };
    this.middlewares.push(loggingMW);
  }

  addTransformMiddleware() {
    const transformMW = function (ctx) {
      // Step 18: read params from context
      const rawParams = ctx.params;
      // Step 19: transform params (format for shell)
      const transformed = rawParams.replace(/,/g, " ");
      // Step 20: write back to context
      ctx.params = transformed;
      // Step 21: update metadata with transform record
      ctx.metadata.transformed = true;
      ctx.metadata.original_params = rawParams;
      return ctx;
    };
    this.middlewares.push(transformMW);
  }

  // Steps 16-21: each middleware reads and modifies the context
  process(ctx) {
    let current = ctx;
    for (let i = 0; i < this.middlewares.length; i++) {
      const mw = this.middlewares[i];
      current = mw(current);
    }
    return current;
  }
}

class DfcCommandRegistry {
  constructor() {
    this._handlers = {
      deploy: "dfc_deploy_handler",
      backup: "dfc_backup_handler",
      migrate: "dfc_migrate_handler",
      shell: "dfc_shell_handler",
    };
  }

  // Step 24 (from caller): resolve plugin name to handler
  getHandler(pluginName) {
    if (this._handlers[pluginName]) {
      const handler = this._handlers[pluginName];
      return handler;
    }
    // Fallback: use the plugin name itself as the handler
    const fallback = pluginName + "_handler";
    return fallback;
  }

  listPlugins() {
    return Object.keys(this._handlers);
  }
}

class DfcConfigLoader {
  constructor() {
    this.configPath = "/etc/plugins.conf";
    this.settings = {};
  }

  load() {
    this.settings = {
      timeout: 30,
      shell: "/bin/bash",
      allow_exec: true,
    };
    return this.settings;
  }

  getShell() {
    if (!this.settings.shell) {
      this.load();
    }
    const shellPath = this.settings.shell;
    return shellPath;
  }
}

module.exports = { DfcRequestContext, DfcMiddlewareChain, DfcCommandRegistry, DfcConfigLoader };
