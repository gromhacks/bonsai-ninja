import java.util.*;

/**
 * Deep cross-file flow chain: Middleware and helper classes.
 *
 * Provides DfcRequestContext, DfcMiddlewareChain, and DfcCommandRegistry used by
 * the main pipeline. Data flows through middleware transformations before
 * being passed to the executor.
 */

/**
 * DfcRequestContext carries command data through the middleware pipeline.
 */
class DfcRequestContext {
    private String command;
    private String params;
    private Map<String, String> metadata;
    private List<String> traceLog;

    // Step 12 (from caller): store command and params
    public DfcRequestContext(String command, String params) {
        this.command = command;
        this.params = params;
        this.metadata = new HashMap<>();
        this.traceLog = new ArrayList<>();
    }

    public String getCommand() {
        return this.command;
    }

    public void setCommand(String command) {
        this.command = command;
    }

    public String getParams() {
        return this.params;
    }

    public void setParams(String params) {
        this.params = params;
    }

    public Map<String, String> getMetadata() {
        return this.metadata;
    }

    public void appendTrace(String entry) {
        this.traceLog.add(entry);
    }

    public String getFullPayload() {
        String payload = this.command + " --args " + this.params;
        return payload;
    }
}

/**
 * DfcMiddlewareChain processes a DfcRequestContext through middleware functions.
 */
class DfcMiddlewareChain {
    private List<DfcMiddleware> middlewares;

    public DfcMiddlewareChain() {
        this.middlewares = new ArrayList<>();
    }

    public void addLoggingMiddleware() {
        this.middlewares.add(new DfcMiddleware() {
            public DfcRequestContext apply(DfcRequestContext ctx) {
                // Step 17: read command from context
                String loggedCmd = ctx.getCommand();
                ctx.appendTrace("LOG: " + loggedCmd);
                return ctx;
            }
        });
    }

    public void addTransformMiddleware() {
        this.middlewares.add(new DfcMiddleware() {
            public DfcRequestContext apply(DfcRequestContext ctx) {
                // Step 18: read params from context
                String rawParams = ctx.getParams();
                // Step 19: transform params (format for shell)
                String transformed = rawParams.replace(",", " ");
                // Step 20: write back to context
                ctx.setParams(transformed);
                // Step 21: update metadata with transform record
                ctx.getMetadata().put("transformed", "true");
                ctx.getMetadata().put("original_params", rawParams);
                return ctx;
            }
        });
    }

    // Steps 16-21: each middleware reads and modifies the context
    public DfcRequestContext process(DfcRequestContext ctx) {
        DfcRequestContext current = ctx;
        for (DfcMiddleware mw : this.middlewares) {
            current = mw.apply(current);
        }
        return current;
    }
}

/**
 * DfcMiddleware interface for middleware functions.
 */
interface DfcMiddleware {
    DfcRequestContext apply(DfcRequestContext ctx);
}

/**
 * DfcCommandRegistry is a registry of available plugin command handlers.
 */
class DfcCommandRegistry {
    private Map<String, String> handlers;

    public DfcCommandRegistry() {
        this.handlers = new HashMap<>();
        this.handlers.put("deploy", "dfc_deploy_handler");
        this.handlers.put("backup", "dfc_backup_handler");
        this.handlers.put("migrate", "dfc_migrate_handler");
        this.handlers.put("shell", "dfc_shell_handler");
    }

    // Step 24 (from caller): resolve plugin name to handler
    public String getHandler(String pluginName) {
        if (this.handlers.containsKey(pluginName)) {
            String handler = this.handlers.get(pluginName);
            return handler;
        }
        // Fallback: use the plugin name itself as the handler
        String fallback = pluginName + "_handler";
        return fallback;
    }

    public List<String> listPlugins() {
        return new ArrayList<>(this.handlers.keySet());
    }
}

/**
 * DfcConfigLoader loads configuration that affects command execution.
 */
class DfcConfigLoader {
    private String configPath;
    private Map<String, String> settings;

    public DfcConfigLoader() {
        this.configPath = "/etc/plugins.conf";
        this.settings = new HashMap<>();
    }

    public Map<String, String> load() {
        this.settings.put("timeout", "30");
        this.settings.put("shell", "/bin/bash");
        this.settings.put("allow_exec", "true");
        return this.settings;
    }

    public String getShell() {
        if (!this.settings.containsKey("shell")) {
            this.load();
        }
        String shellPath = this.settings.get("shell");
        return shellPath;
    }
}
