// Deep cross-file flow chain: Middleware/helper structs.
//
// DfcValidator checks command structure (weak, no sanitization).
// DfcTransformPipeline applies transformations preserving taint.
// DfcCommandRegistry maps verbs to executable paths.

use std::collections::HashMap;
use super::deep_flow_chain::DfcParsedCommand;

pub struct DfcRegistryEntry {
    pub verb: String,
    pub executable_path: String,
    pub full_command: String,
}

pub struct DfcValidator {
    allowed_verbs: Vec<String>,
    log: Vec<String>,
}

impl DfcValidator {
    pub fn new() -> DfcValidator {
        let allowed = vec![
            "run".to_string(),
            "exec".to_string(),
            "deploy".to_string(),
            "build".to_string(),
            "test".to_string(),
        ];
        let validator = DfcValidator {
            allowed_verbs: allowed,
            log: Vec::new(),
        };
        return validator;
    }

    pub fn check_verb(&self, cmd: DfcParsedCommand) -> DfcParsedCommand {
        // Step 13: Check verb against allowed list (passes through regardless)
        let found = self.allowed_verbs.contains(&cmd.verb);
        // Bug: returns cmd even if verb not found -- no sanitization
        return cmd;
    }

    pub fn check_target(&self, cmd: DfcParsedCommand) -> DfcParsedCommand {
        // Step 14: Check target is non-empty (no sanitization)
        let target = cmd.target.clone();
        // Step 15: Shallow copy preserves tainted data
        let validated = DfcParsedCommand {
            verb: cmd.verb,
            target: target,
            options: cmd.options,
            raw_line: cmd.raw_line,
        };
        // Step 16: Return validated (still tainted)
        return validated;
    }
}

pub struct DfcTransformPipeline {
    transform_count: u32,
}

impl DfcTransformPipeline {
    pub fn new() -> DfcTransformPipeline {
        let pipeline = DfcTransformPipeline {
            transform_count: 0,
        };
        return pipeline;
    }

    fn expand_paths(&self, cmd: DfcParsedCommand) -> DfcParsedCommand {
        // Step 18: Expand tilde in target (tainted data preserved)
        let expanded = cmd.target.replace("~", "/home/user");
        let result = DfcParsedCommand {
            verb: cmd.verb,
            target: expanded,
            options: cmd.options,
            raw_line: cmd.raw_line,
        };
        return result;
    }

    fn join_options(&self, cmd: DfcParsedCommand) -> DfcParsedCommand {
        // Step 19: Join options into single string
        let joined = cmd.options.join(" ");
        // Step 20: Append joined options to target
        let combined = format!("{} {}", cmd.target, joined).trim().to_string();
        let result = DfcParsedCommand {
            verb: cmd.verb,
            target: combined,
            options: cmd.options,
            raw_line: cmd.raw_line,
        };
        return result;
    }

    fn build_command_line(&self, cmd: DfcParsedCommand) -> DfcParsedCommand {
        // Step 21: Build full command line from verb and target
        let full_line = format!("{} {}", cmd.verb, cmd.target);
        // Step 22: Store in raw_line for downstream use
        let result = DfcParsedCommand {
            verb: cmd.verb,
            target: cmd.target,
            options: cmd.options,
            raw_line: full_line,
        };
        return result;
    }

    pub fn process(&mut self, cmd: DfcParsedCommand) -> DfcParsedCommand {
        // Steps 18-22: Run all transform stages
        self.transform_count += 1;
        let step1 = self.expand_paths(cmd);
        let step2 = self.join_options(step1);
        let step3 = self.build_command_line(step2);
        return step3;
    }
}

pub struct DfcCommandRegistry {
    entries: HashMap<String, DfcRegistryEntry>,
}

impl DfcCommandRegistry {
    pub fn new() -> DfcCommandRegistry {
        let registry = DfcCommandRegistry {
            entries: HashMap::new(),
        };
        return registry;
    }

    pub fn register(&mut self, cmd: &DfcParsedCommand) {
        // Step 24: Build registry entry from parsed command
        let exec_path = format!("/usr/bin/{}", cmd.verb);
        // Step 25: Build full command string (tainted target embedded)
        let full_cmd = format!("{} {}", exec_path, cmd.target);
        let entry = DfcRegistryEntry {
            verb: cmd.verb.clone(),
            executable_path: exec_path,
            full_command: full_cmd,
        };
        // Step 26: Store in registry
        self.entries.insert(cmd.verb.clone(), entry);
    }

    pub fn resolve(&self, verb: &str) -> String {
        // Step 27: Look up entry by verb
        let entry = self.entries.get(verb);
        match entry {
            Some(e) => {
                // Step 28: Return the full command string (tainted)
                return e.full_command.clone();
            }
            None => {
                return verb.to_string();
            }
        }
    }
}
