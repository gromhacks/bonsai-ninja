/**
 * Deep cross-file flow chain: Final executor with dangerous sink.
 *
 * Receives resolved command strings and executes them via child_process.exec.
 * The taint chain terminates here at exec().
 */

import { exec, execSync } from "child_process";

interface DfcExecResult {
  output: string;
  exitCode: number;
  command: string;
}

interface DfcExecConfig {
  shell: string;
  timeout: number;
  env: Record<string, string>;
}

class DfcConfigBuilder {
  private shell: string;
  private timeout: number;
  private envVars: Record<string, string>;

  constructor() {
    this.shell = "/bin/sh";
    this.timeout = 30000;
    this.envVars = {};
  }

  setShell(shell: string): DfcConfigBuilder {
    this.shell = shell;
    return this;
  }

  setTimeout(ms: number): DfcConfigBuilder {
    this.timeout = ms;
    return this;
  }

  addEnv(key: string, value: string): DfcConfigBuilder {
    this.envVars[key] = value;
    return this;
  }

  build(): DfcExecConfig {
    return {
      shell: this.shell,
      timeout: this.timeout,
      env: { ...this.envVars },
    };
  }
}

export class DfcExecutor {
  private history: string[];
  private config: DfcExecConfig;

  constructor() {
    this.history = [];
    // Step 30: Build default execution config
    const builder = new DfcConfigBuilder();
    this.config = builder.setShell("/bin/bash").setTimeout(60000).build();
  }

  run(command: string, environment: string): string {
    // Step 30: Prepare environment prefix
    const envPrefix = this._buildEnvPrefix(environment);
    // Step 31: Combine prefix with command (tainted data preserved)
    const fullCommand = envPrefix + command;
    // Step 32: Record in history
    this.history.push(fullCommand);
    // Step 33: Delegate to internal execution
    const result = this._executeCommand(fullCommand);
    return result.output;
  }

  private _buildEnvPrefix(environment: string): string {
    if (environment === "production") {
      return "";
    }
    return "echo [" + environment + "] && ";
  }

  private _executeCommand(command: string): DfcExecResult {
    // Step 34: Prepare command for execution
    const cleaned = command.trim();
    // Step 35: SINK -- tainted data reaches child_process.exec
    const output = execSync(cleaned, {
      shell: this.config.shell,
      timeout: this.config.timeout,
      encoding: "utf-8",
    });
    const result: DfcExecResult = {
      output: String(output),
      exitCode: 0,
      command: cleaned,
    };
    return result;
  }

  runAsync(command: string, callback: (err: Error | null, out: string) => void): void {
    // Alternative async sink via child_process.exec
    exec(command, { shell: this.config.shell }, (error, stdout, stderr) => {
      if (error) {
        callback(error, stderr);
      } else {
        callback(null, stdout);
      }
    });
  }
}
