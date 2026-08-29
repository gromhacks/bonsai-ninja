/**
 * Deep cross-file flow chain: Plugin command executor pipeline.
 *
 * User input from process.stdin flows through ~35 steps across 3 files,
 * 5+ functions, 3+ classes, crossing variable assignments, method calls,
 * constructors, object access, string concatenation, conditionals, and
 * loops before reaching child_process.exec() (SINK).
 *
 * Flow: process.stdin -> parse -> validate -> transform -> registry.lookup
 *       -> executor.run -> child_process.exec()
 *
 * All class/function names prefixed with Dfc to avoid cross-file collisions.
 */

const { DfcRequestContext, DfcMiddlewareChain, DfcCommandRegistry } = require("./deep_flow_helpers");
const { DfcPluginExecutor } = require("./deep_flow_sink");

class DfcCommandParser {
  constructor() {
    this.delimiter = "::";
    this.rawBuffer = "";
  }

  // Step 1: read user input (SOURCE)
  readInput(inputLine) {
    const rawText = inputLine;
    // Step 2: store in instance field
    this.rawBuffer = rawText;
    return this.rawBuffer;
  }

  // Step 3-4: tokenize into parts
  tokenize(text) {
    const parts = text.trim().split(this.delimiter);
    const tokens = {
      plugin_name: parts.length > 0 ? parts[0] : "",
      action: parts.length > 1 ? parts[1] : "default",
      arguments: parts.length > 2 ? parts.slice(2).join(this.delimiter) : "",
    };
    return tokens;
  }

  // Step 5-7: normalize tokens into a command descriptor
  normalize(tokens) {
    // Step 5: normalize plugin name
    const pluginId = tokens.plugin_name.toLowerCase().replace(/-/g, "_");
    // Step 6: normalize action
    const normalizedAction = tokens.action.trim();
    // Step 7: combine into descriptor
    const descriptor = {
      id: pluginId,
      action: normalizedAction,
      args: tokens.arguments,
      full_command: pluginId + "." + normalizedAction,
    };
    return descriptor;
  }
}

class DfcInputValidator {
  constructor() {
    this.errors = [];
  }

  // Step 8-10: validate the descriptor
  checkFormat(descriptor) {
    // Step 8: extract command string
    const cmdStr = descriptor.full_command;
    // Step 9: extract arguments
    const cmdArgs = descriptor.args;
    // Step 10: build validated payload (no real sanitization -- vulnerable)
    const validated = {
      command: cmdStr,
      parameters: cmdArgs,
      is_valid: cmdStr.length > 0,
    };
    return validated;
  }
}

// Step 11-13: wrap validated payload into a DfcRequestContext
function dfcBuildRequest(validated) {
  // Step 11: extract fields
  const command = validated.command;
  const params = validated.parameters;
  // Step 12: create context object (cross-file, into deep_flow_helpers.js)
  const ctx = new DfcRequestContext(command, params);
  // Step 13: attach metadata
  ctx.metadata.origin = "cli";
  ctx.metadata.validated = validated.is_valid;
  return ctx;
}

// Step 14-16: run middleware chain on the request context
function dfcApplyMiddleware(ctx) {
  // Step 14: create middleware chain (cross-file)
  const chain = new DfcMiddlewareChain();
  // Step 15: register built-in middleware
  chain.addLoggingMiddleware();
  chain.addTransformMiddleware();
  // Step 16: process through chain
  const processedCtx = chain.process(ctx);
  return processedCtx;
}

// Step 22-26: dispatch processed context to the executor
function dfcDispatchToExecutor(processedCtx) {
  // Step 22: extract processed command
  const finalCommand = processedCtx.command;
  const finalParams = processedCtx.params;
  // Step 23: build execution string
  const execString = finalCommand + " " + finalParams;
  // Step 24: create registry and look up plugin
  const registry = new DfcCommandRegistry();
  const pluginName = finalCommand.split(".")[0];
  const handler = registry.getHandler(pluginName);
  // Step 25: wrap in executor (cross-file, into deep_flow_sink.js)
  const executor = new DfcPluginExecutor(handler);
  // Step 26: pass to executor for final processing
  const result = executor.prepareAndRun(execString, processedCtx.metadata);
  return result;
}

function dfcMain(inputLine) {
  const parser = new DfcCommandParser();
  const validator = new DfcInputValidator();

  // Steps 1-2: read input
  const raw = parser.readInput(inputLine);
  // Steps 3-4: tokenize
  const tokens = parser.tokenize(raw);
  // Steps 5-7: normalize
  const descriptor = parser.normalize(tokens);
  // Steps 8-10: validate
  const validated = validator.checkFormat(descriptor);
  // Steps 11-13: build request context
  const ctx = dfcBuildRequest(validated);
  // Steps 14-21: apply middleware
  const processed = dfcApplyMiddleware(ctx);
  // Steps 22-35: dispatch and execute
  const result = dfcDispatchToExecutor(processed);

  if (result !== null) {
    console.log("Execution result: " + result);
  }
}

// Read from stdin (SOURCE)
const readline = require("readline");
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", function (line) {
  dfcMain(line);
});
