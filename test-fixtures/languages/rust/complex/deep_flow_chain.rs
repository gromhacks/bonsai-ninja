// Deep cross-file flow chain: Entry point reading user input through a
// processing pipeline.
//
// Flow: stdin -> parse -> validate -> transform -> registry -> executor -> Command
// 30+ steps across 3 files, 5+ function calls deep.
//
// Uses "Dfc" prefix on all types. Standard library only.

mod deep_flow_helpers;
mod deep_flow_sink;

use std::io;
use std::collections::HashMap;

pub struct DfcRawInput {
    pub line: String,
    pub timestamp: u64,
}

pub struct DfcTokenSet {
    pub parts: Vec<String>,
    pub count: usize,
}

pub struct DfcParsedCommand {
    pub verb: String,
    pub target: String,
    pub options: Vec<String>,
    pub raw_line: String,
}

fn dfc_read_user_input() -> DfcRawInput {
    // Step 1: Read from stdin (SOURCE)
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer).unwrap();
    // Step 2: Wrap in raw input structure
    let raw = DfcRawInput {
        line: buffer.trim().to_string(),
        timestamp: 1234567890,
    };
    return raw;
}

fn dfc_tokenize(raw: &DfcRawInput) -> DfcTokenSet {
    // Step 3: Extract line from raw input
    let line = raw.line.clone();
    // Step 4: Split into tokens
    let parts: Vec<String> = line.split_whitespace()
        .map(String::from)
        .collect();
    // Step 5: Build token set
    let count = parts.len();
    let tokens = DfcTokenSet {
        parts: parts,
        count: count,
    };
    return tokens;
}

fn dfc_build_parsed_command(tokens: DfcTokenSet, raw_line: String) -> DfcParsedCommand {
    // Step 6: Extract verb from first token
    let verb = tokens.parts.get(0).cloned().unwrap_or_default();
    // Step 7: Extract target from second token
    let target = tokens.parts.get(1).cloned().unwrap_or_default();
    // Step 8: Remaining tokens become options
    let options: Vec<String> = if tokens.count > 2 {
        tokens.parts[2..].to_vec()
    } else {
        Vec::new()
    };
    // Step 9: Assemble parsed command
    let cmd = DfcParsedCommand {
        verb: verb,
        target: target,
        options: options,
        raw_line: raw_line,
    };
    return cmd;
}

fn dfc_normalize_verb(cmd: DfcParsedCommand) -> DfcParsedCommand {
    // Step 10: Normalize verb to lowercase
    let lower = cmd.verb.to_lowercase();
    let normalized = DfcParsedCommand {
        verb: lower,
        target: cmd.target,
        options: cmd.options,
        raw_line: cmd.raw_line,
    };
    return normalized;
}

fn dfc_attach_metadata(cmd: DfcParsedCommand) -> DfcParsedCommand {
    // Step 11: Attach trace metadata to options
    let mut opts = cmd.options;
    opts.push("--trace-id=42".to_string());
    let enriched = DfcParsedCommand {
        verb: cmd.verb,
        target: cmd.target,
        options: opts,
        raw_line: cmd.raw_line,
    };
    return enriched;
}

fn dfc_run_validation(cmd: DfcParsedCommand) -> DfcParsedCommand {
    // Step 12: Create validator (cross-file, deep_flow_helpers.rs)
    let validator = deep_flow_helpers::DfcValidator::new();
    // Step 13: Validate verb
    let checked = validator.check_verb(cmd);
    // Step 14: Validate target
    let validated = validator.check_target(checked);
    return validated;
}

fn dfc_run_transform(cmd: DfcParsedCommand) -> DfcParsedCommand {
    // Step 17: Create transform pipeline (cross-file)
    let mut pipeline = deep_flow_helpers::DfcTransformPipeline::new();
    // Steps 18-22: Run through transforms
    let transformed = pipeline.process(cmd);
    return transformed;
}

fn dfc_register_and_resolve(cmd: &DfcParsedCommand) -> String {
    // Step 23: Create command registry (cross-file)
    let mut registry = deep_flow_helpers::DfcCommandRegistry::new();
    // Step 24: Register the command
    registry.register(cmd);
    // Steps 25-28: Resolve to executable command string
    let resolved = registry.resolve(&cmd.verb);
    return resolved;
}

fn dfc_dispatch_to_executor(command_str: String, env: String) -> String {
    // Step 29: Create executor (cross-file, deep_flow_sink.rs)
    let executor = deep_flow_sink::DfcExecutor::new();
    // Steps 30-35: Execute the command
    let result = executor.run(command_str, env);
    return result;
}

pub fn dfc_main() {
    // Steps 1-2: Read user input
    let raw = dfc_read_user_input();
    let raw_line = raw.line.clone();

    // Steps 3-5: Tokenize
    let tokens = dfc_tokenize(&raw);
    // Steps 6-9: Parse into command
    let parsed = dfc_build_parsed_command(tokens, raw_line);
    // Step 10: Normalize
    let normalized = dfc_normalize_verb(parsed);
    // Step 11: Attach metadata
    let enriched = dfc_attach_metadata(normalized);
    // Steps 12-16: Validate (cross-file)
    let validated = dfc_run_validation(enriched);
    // Steps 17-22: Transform (cross-file)
    let transformed = dfc_run_transform(validated);
    // Steps 23-28: Register and resolve (cross-file)
    let command_str = dfc_register_and_resolve(&transformed);
    // Steps 29-35: Execute (cross-file)
    let result = dfc_dispatch_to_executor(command_str, "production".to_string());

    println!("Result: {}", result);
}

fn main() {
    dfc_main();
}
