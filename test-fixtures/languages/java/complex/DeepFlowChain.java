import java.util.*;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * Deep cross-file flow chain: Plugin command executor pipeline.
 *
 * User input from Scanner flows through ~35 steps across 3 files, 5+ functions,
 * 3+ classes, crossing variable assignments, method calls, constructors, map access,
 * string concatenation, conditionals, and loops before reaching Runtime.exec().
 *
 * Flow: Scanner.nextLine() -> parse -> validate -> transform -> registry.lookup
 *       -> executor.run -> Runtime.getRuntime().exec() (SINK)
 *
 * All class/method names prefixed with Dfc to avoid cross-file collisions.
 */
public class DeepFlowChain {

    @Retention(RetentionPolicy.RUNTIME)
    @interface DfcAudited {}

    /**
     * DfcCommandParser parses raw user input into structured command objects.
     */
    static class DfcCommandParser {
        private String delimiter;
        private String rawBuffer;

        public DfcCommandParser() {
            this.delimiter = "::";
            this.rawBuffer = "";
        }

        // Step 1: read user input (SOURCE)
        public String readInput() {
            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter plugin command: ");
            String rawText = scanner.nextLine();
            // Step 2: store in instance field
            this.rawBuffer = rawText;
            return this.rawBuffer;
        }

        // Step 3-4: tokenize into parts
        public Map<String, String> tokenize(String text) {
            String[] parts = text.trim().split(this.delimiter);
            String pluginName = parts.length > 0 ? parts[0] : "";
            String action = parts.length > 1 ? parts[1] : "default";
            String arguments = "";
            if (parts.length > 2) {
                StringBuilder sb = new StringBuilder();
                for (int i = 2; i < parts.length; i++) {
                    if (i > 2) {
                        sb.append(this.delimiter);
                    }
                    sb.append(parts[i]);
                }
                arguments = sb.toString();
            }
            Map<String, String> tokens = new HashMap<>();
            tokens.put("plugin_name", pluginName);
            tokens.put("action", action);
            tokens.put("arguments", arguments);
            return tokens;
        }

        // Step 5-7: normalize tokens into a command descriptor
        public Map<String, String> normalize(Map<String, String> tokens) {
            // Step 5: normalize plugin name
            String pluginId = tokens.get("plugin_name").toLowerCase().replace("-", "_");
            // Step 6: normalize action
            String normalizedAction = tokens.get("action").trim();
            // Step 7: combine into descriptor
            Map<String, String> descriptor = new HashMap<>();
            descriptor.put("id", pluginId);
            descriptor.put("action", normalizedAction);
            descriptor.put("args", tokens.get("arguments"));
            descriptor.put("full_command", pluginId + "." + normalizedAction);
            return descriptor;
        }
    }

    /**
     * DfcInputValidator validates parsed command descriptors.
     */
    static class DfcInputValidator {
        private List<String> errors;

        public DfcInputValidator() {
            this.errors = new ArrayList<>();
        }

        // Step 8-10: validate the descriptor
        public Map<String, String> checkFormat(Map<String, String> descriptor) {
            // Step 8: extract command string
            String cmdStr = descriptor.get("full_command");
            // Step 9: extract arguments
            String cmdArgs = descriptor.get("args");
            // Step 10: build validated payload (no real sanitization -- vulnerable)
            String isValid = cmdStr.length() > 0 ? "true" : "false";
            Map<String, String> validated = new HashMap<>();
            validated.put("command", cmdStr);
            validated.put("parameters", cmdArgs);
            validated.put("is_valid", isValid);
            return validated;
        }
    }

    // Step 11-13: wrap validated payload into a DfcRequestContext
    public static DfcRequestContext dfcBuildRequest(Map<String, String> validated) {
        // Step 11: extract fields
        String command = validated.get("command");
        String params = validated.get("parameters");
        // Step 12: create context object (cross-file, into DeepFlowHelpers.java)
        DfcRequestContext ctx = new DfcRequestContext(command, params);
        // Step 13: attach metadata
        ctx.getMetadata().put("origin", "cli");
        ctx.getMetadata().put("validated", validated.get("is_valid"));
        return ctx;
    }

    // Step 14-16: run middleware chain on the request context
    public static DfcRequestContext dfcApplyMiddleware(DfcRequestContext ctx) {
        // Step 14: create middleware chain (cross-file)
        DfcMiddlewareChain chain = new DfcMiddlewareChain();
        // Step 15: register built-in middleware
        chain.addLoggingMiddleware();
        chain.addTransformMiddleware();
        // Step 16: process through chain
        DfcRequestContext processedCtx = chain.process(ctx);
        return processedCtx;
    }

    // Step 22-26: dispatch processed context to the executor
    public static String dfcDispatchToExecutor(DfcRequestContext processedCtx) {
        // Step 22: extract processed command
        String finalCommand = processedCtx.getCommand();
        String finalParams = processedCtx.getParams();
        // Step 23: build execution string
        String execString = finalCommand + " " + finalParams;
        // Step 24: create registry and look up plugin
        DfcCommandRegistry registry = new DfcCommandRegistry();
        String pluginName = finalCommand.split("\\.")[0];
        String handler = registry.getHandler(pluginName);
        // Step 25: wrap in executor (cross-file, into DeepFlowSink.java)
        DfcPluginExecutor executor = new DfcPluginExecutor(handler);
        // Step 26: pass to executor for final processing
        String result = executor.prepareAndRun(execString, processedCtx.getMetadata());
        return result;
    }

    // Entry point: orchestrates the full chain
    @DfcAudited
    public static void main(String[] args) {
        DfcCommandParser parser = new DfcCommandParser();
        DfcInputValidator validator = new DfcInputValidator();

        // Steps 1-2: read input
        String raw = parser.readInput();
        // Steps 3-4: tokenize
        Map<String, String> tokens = parser.tokenize(raw);
        // Steps 5-7: normalize
        Map<String, String> descriptor = parser.normalize(tokens);
        // Steps 8-10: validate
        Map<String, String> validated = validator.checkFormat(descriptor);
        // Steps 11-13: build request context
        DfcRequestContext ctx = dfcBuildRequest(validated);
        // Steps 14-21: apply middleware
        DfcRequestContext processed = dfcApplyMiddleware(ctx);
        // Steps 22-35: dispatch and execute
        String result = dfcDispatchToExecutor(processed);

        if (result != null) {
            System.out.println("Execution result: " + result);
        }
    }
}
