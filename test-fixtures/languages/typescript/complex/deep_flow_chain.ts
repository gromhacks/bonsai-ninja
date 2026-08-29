/**
 * Deep cross-file flow chain: Entry point reading user input through a
 * processing pipeline.
 *
 * Flow: readline -> parse -> validate -> transform -> registry -> executor -> exec()
 * 30+ steps across 3 files, 5+ function calls deep.
 *
 * Uses "Dfc" prefix on all types. Standard library only.
 */

import * as readline from "readline";
import { DfcValidator, DfcTransformPipeline, DfcCommandRegistry } from "./deep_flow_helpers";
import { DfcExecutor } from "./deep_flow_sink";

interface DfcRawInput {
  line: string;
  timestamp: number;
}

interface DfcParsedCommand {
  verb: string;
  target: string;
  options: string[];
  rawLine: string;
}

interface DfcTokenSet {
  parts: string[];
  count: number;
}

class DfcInputReader {
  private rl: readline.Interface;

  constructor() {
    this.rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
  }

  readLine(): Promise<DfcRawInput> {
    return new Promise((resolve) => {
      // Step 1: Read user input from readline (SOURCE)
      this.rl.question("Enter command> ", (answer: string) => {
        // Step 2: Wrap in raw input structure
        const raw: DfcRawInput = {
          line: answer,
          timestamp: Date.now(),
        };
        resolve(raw);
      });
    });
  }

  close(): void {
    this.rl.close();
  }
}

class DfcParser {
  private delimiter: string;

  constructor(delimiter: string = " ") {
    this.delimiter = delimiter;
  }

  tokenize(raw: DfcRawInput): DfcTokenSet {
    // Step 3: Extract line from raw input
    const line = raw.line;
    // Step 4: Split into tokens
    const parts = line.split(this.delimiter).filter((p: string) => p.length > 0);
    // Step 5: Build token set
    const tokens: DfcTokenSet = {
      parts: parts,
      count: parts.length,
    };
    return tokens;
  }

  buildCommand(tokens: DfcTokenSet, rawLine: string): DfcParsedCommand {
    // Step 6: Extract verb from first token
    const verb = tokens.parts[0] || "";
    // Step 7: Extract target from second token
    const target = tokens.parts[1] || "";
    // Step 8: Remaining tokens become options
    const options = tokens.parts.slice(2);
    // Step 9: Assemble parsed command
    const cmd: DfcParsedCommand = {
      verb: verb,
      target: target,
      options: options,
      rawLine: rawLine,
    };
    return cmd;
  }
}

function dfcNormalizeVerb(cmd: DfcParsedCommand): DfcParsedCommand {
  // Step 10: Normalize verb to lowercase
  const normalized: DfcParsedCommand = {
    verb: cmd.verb.toLowerCase(),
    target: cmd.target,
    options: cmd.options,
    rawLine: cmd.rawLine,
  };
  return normalized;
}

function dfcAttachMetadata(cmd: DfcParsedCommand): DfcParsedCommand {
  // Step 11: Attach metadata to options
  const enriched: DfcParsedCommand = {
    verb: cmd.verb,
    target: cmd.target,
    options: [...cmd.options, "--trace-id=" + String(Date.now())],
    rawLine: cmd.rawLine,
  };
  return enriched;
}

function dfcRunValidation(cmd: DfcParsedCommand): DfcParsedCommand {
  // Step 12: Create validator (cross-file, deep_flow_helpers.ts)
  const validator = new DfcValidator();
  // Step 13: Validate verb (weak check, passes tainted data through)
  const checked = validator.checkVerb(cmd);
  // Step 14: Validate target (no real sanitization)
  const validated = validator.checkTarget(checked);
  return validated;
}

function dfcRunTransform(cmd: DfcParsedCommand): DfcParsedCommand {
  // Step 17: Create transform pipeline (cross-file)
  const pipeline = new DfcTransformPipeline();
  // Steps 18-22: Run through transforms
  const transformed = pipeline.process(cmd);
  return transformed;
}

function dfcRegisterAndResolve(cmd: DfcParsedCommand): string {
  // Step 23: Create command registry (cross-file)
  const registry = new DfcCommandRegistry();
  // Step 24: Register the command
  registry.register(cmd);
  // Steps 25-28: Resolve to executable command string
  const resolved = registry.resolve(cmd.verb);
  return resolved;
}

function dfcDispatchToExecutor(commandStr: string, env: string): string {
  // Step 29: Create executor (cross-file, deep_flow_sink.ts)
  const executor = new DfcExecutor();
  // Steps 30-35: Execute the command
  const result = executor.run(commandStr, env);
  return result;
}

export async function dfcMain(): Promise<void> {
  const reader = new DfcInputReader();
  const parser = new DfcParser();

  // Steps 1-2: Read user input
  const raw = await reader.readLine();
  reader.close();

  // Steps 3-5: Tokenize
  const tokens = parser.tokenize(raw);
  // Steps 6-9: Parse into command
  const parsed = parser.buildCommand(tokens, raw.line);
  // Step 10: Normalize
  const normalized = dfcNormalizeVerb(parsed);
  // Step 11: Attach metadata
  const enriched = dfcAttachMetadata(normalized);
  // Steps 12-16: Validate (cross-file)
  const validated = dfcRunValidation(enriched);
  // Steps 17-22: Transform (cross-file)
  const transformed = dfcRunTransform(validated);
  // Steps 23-28: Register and resolve (cross-file)
  const commandStr = dfcRegisterAndResolve(transformed);
  // Steps 29-35: Execute (cross-file)
  const result = dfcDispatchToExecutor(commandStr, "production");

  console.log("Result: " + result);
}

dfcMain();
