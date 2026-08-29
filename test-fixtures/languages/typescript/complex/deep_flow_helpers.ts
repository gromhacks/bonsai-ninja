/**
 * Deep cross-file flow chain: Middleware/helper classes.
 *
 * DfcValidator checks command structure (weak, no sanitization).
 * DfcTransformPipeline applies transformations preserving taint.
 * DfcCommandRegistry maps verbs to executable paths.
 */

interface DfcParsedCommand {
  verb: string;
  target: string;
  options: string[];
  rawLine: string;
}

interface DfcRegistryEntry {
  verb: string;
  executablePath: string;
  fullCommand: string;
}

export class DfcValidator {
  private allowedVerbs: string[];
  private log: string[];

  constructor() {
    this.allowedVerbs = ["run", "exec", "deploy", "build", "test"];
    this.log = [];
  }

  checkVerb(cmd: DfcParsedCommand): DfcParsedCommand {
    // Step 13: Check verb against allowed list (passes through regardless)
    const found = this.allowedVerbs.indexOf(cmd.verb) >= 0;
    this.log.push("verb-check:" + cmd.verb + ":" + String(found));
    // Bug: returns cmd even if verb not found
    return cmd;
  }

  checkTarget(cmd: DfcParsedCommand): DfcParsedCommand {
    // Step 14: Check target is non-empty (no sanitization)
    const target = cmd.target;
    if (target.length === 0) {
      this.log.push("target-check:empty");
    }
    // Step 15: Shallow copy preserves tainted data
    const validated: DfcParsedCommand = {
      verb: cmd.verb,
      target: target,
      options: cmd.options.slice(),
      rawLine: cmd.rawLine,
    };
    // Step 16: Log validation result
    this.log.push("target-check:" + target + ":ok");
    return validated;
  }
}

export class DfcTransformPipeline {
  private stages: Array<(cmd: DfcParsedCommand) => DfcParsedCommand>;

  constructor() {
    this.stages = [];
    this.stages.push(this._expandPaths.bind(this));
    this.stages.push(this._joinOptions.bind(this));
    this.stages.push(this._buildCommandLine.bind(this));
  }

  private _expandPaths(cmd: DfcParsedCommand): DfcParsedCommand {
    // Step 18: Expand tilde in target (tainted data preserved)
    const expanded = cmd.target.replace("~", "/home/user");
    return {
      verb: cmd.verb,
      target: expanded,
      options: cmd.options,
      rawLine: cmd.rawLine,
    };
  }

  private _joinOptions(cmd: DfcParsedCommand): DfcParsedCommand {
    // Step 19: Join options into target string
    const joined = cmd.options.join(" ");
    // Step 20: Append joined options to target
    const combined = cmd.target + " " + joined;
    return {
      verb: cmd.verb,
      target: combined.trim(),
      options: cmd.options,
      rawLine: cmd.rawLine,
    };
  }

  private _buildCommandLine(cmd: DfcParsedCommand): DfcParsedCommand {
    // Step 21: Build full command line from verb and target
    const fullLine = cmd.verb + " " + cmd.target;
    // Step 22: Store in rawLine for downstream use
    return {
      verb: cmd.verb,
      target: cmd.target,
      options: cmd.options,
      rawLine: fullLine,
    };
  }

  process(cmd: DfcParsedCommand): DfcParsedCommand {
    // Steps 18-22: Run all transform stages
    let current = cmd;
    for (const stage of this.stages) {
      current = stage(current);
    }
    return current;
  }
}

export class DfcCommandRegistry {
  private entries: Map<string, DfcRegistryEntry>;

  constructor() {
    this.entries = new Map();
  }

  register(cmd: DfcParsedCommand): void {
    // Step 24: Build registry entry from parsed command
    const execPath = "/usr/bin/" + cmd.verb;
    // Step 25: Build full command string (tainted target embedded)
    const fullCmd = execPath + " " + cmd.target;
    const entry: DfcRegistryEntry = {
      verb: cmd.verb,
      executablePath: execPath,
      fullCommand: fullCmd,
    };
    // Step 26: Store in registry
    this.entries.set(cmd.verb, entry);
  }

  resolve(verb: string): string {
    // Step 27: Look up entry by verb
    const entry = this.entries.get(verb);
    if (!entry) {
      return verb;
    }
    // Step 28: Return the full command string (tainted)
    return entry.fullCommand;
  }
}
