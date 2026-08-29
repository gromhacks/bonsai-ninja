/**
 * Deep cross-file flow chain: Plugin executor (contains dangerous sinks).
 *
 * Receives processed command strings and executes them via child_process.exec().
 * The taint chain terminates here.
 *
 * Contains: DfcPluginExecutor, DfcExecutionConfig, DfcCommandRunner
 */

const { exec } = require("child_process");

class DfcPluginExecutor {
  // Step 25 (from caller): store handler name
  constructor(handlerName) {
    this.handlerName = handlerName;
    this.config = new DfcExecutionConfig();
  }

  prepareAndRun(execString, metadata) {
    // Step 27: build the shell prefix
    const shellPrefix = this.config.getPrefix();
    // Step 28: combine handler name into command
    let handlerCmd = this.handlerName + " " + execString;
    // Step 29: apply metadata-based transformations
    if (metadata.transformed) {
      handlerCmd = handlerCmd + " --transformed";
    }
    // Step 30: wrap in shell invocation
    const fullShellCmd = shellPrefix + " -c '" + handlerCmd + "'";
    // Step 31: pass to the runner
    const runner = new DfcCommandRunner();
    const result = runner.execute(fullShellCmd);
    return result;
  }

  prepareBatch(commands, metadata) {
    const results = [];
    for (let i = 0; i < commands.length; i++) {
      let combined = this.handlerName + " " + commands[i];
      if (metadata.origin === "cli") {
        combined = combined + " --interactive";
      }
      const runner = new DfcCommandRunner();
      const res = runner.execute(combined);
      results.push(res);
    }
    return results;
  }
}

class DfcExecutionConfig {
  constructor() {
    this.shell = "/bin/bash";
    this.timeout = 30;
    this.envVars = {};
  }

  // Step 27: returns the shell path used as command prefix
  getPrefix() {
    const prefix = this.shell;
    return prefix;
  }

  setTimeout(seconds) {
    this.timeout = seconds;
  }
}

class DfcCommandRunner {
  constructor() {
    this.lastExitCode = null;
    this.lastOutput = "";
  }

  execute(commandString) {
    // Step 32: log the command
    const logEntry = "Executing: " + commandString;
    console.log(logEntry);
    // Step 33: format for execution
    const formatted = commandString.trim();
    // Step 34: final variable before sink
    const finalCmd = formatted;
    // Step 35: SINK -- tainted data reaches child_process.exec()
    exec(finalCmd, function (error, stdout, stderr) {
      if (error) {
        console.error("Execution failed: " + error.message);
        return;
      }
      console.log(stdout);
    });
    this.lastOutput = "submitted: " + finalCmd;
    return this.lastOutput;
  }
}

module.exports = { DfcPluginExecutor, DfcExecutionConfig, DfcCommandRunner };
