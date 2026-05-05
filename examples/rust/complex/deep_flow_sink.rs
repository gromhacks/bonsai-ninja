// Deep cross-file flow chain: Final executor with dangerous sink.
//
// Receives resolved command strings and executes them via std::process::Command.
// The taint chain terminates here at Command::new().

use std::process::Command;

pub struct DfcExecConfig {
    pub shell: String,
    pub timeout_sec: u32,
    pub env_vars: Vec<(String, String)>,
}

pub struct DfcExecResult {
    pub output: String,
    pub exit_code: i32,
    pub command: String,
}

pub struct DfcConfigBuilder {
    shell: String,
    timeout: u32,
    env_vars: Vec<(String, String)>,
}

impl DfcConfigBuilder {
    fn new() -> DfcConfigBuilder {
        let builder = DfcConfigBuilder {
            shell: "/bin/sh".to_string(),
            timeout: 30,
            env_vars: Vec::new(),
        };
        return builder;
    }

    fn set_shell(mut self, shell: String) -> DfcConfigBuilder {
        self.shell = shell;
        return self;
    }

    fn set_timeout(mut self, seconds: u32) -> DfcConfigBuilder {
        self.timeout = seconds;
        return self;
    }

    fn build(self) -> DfcExecConfig {
        let config = DfcExecConfig {
            shell: self.shell,
            timeout_sec: self.timeout,
            env_vars: self.env_vars,
        };
        return config;
    }
}

pub struct DfcExecutor {
    history: Vec<String>,
    config: DfcExecConfig,
}

impl DfcExecutor {
    pub fn new() -> DfcExecutor {
        // Step 29: Build default execution config
        let config = DfcConfigBuilder::new()
            .set_shell("/bin/bash".to_string())
            .set_timeout(60)
            .build();
        let executor = DfcExecutor {
            history: Vec::new(),
            config: config,
        };
        return executor;
    }

    pub fn run(mut self, command: String, environment: String) -> String {
        // Step 30: Prepare environment prefix
        let env_prefix = self.build_env_prefix(&environment);
        // Step 31: Combine prefix with command (tainted data preserved)
        let full_command = format!("{}{}", env_prefix, command);
        // Step 32: Record in history
        self.history.push(full_command.clone());
        // Step 33: Delegate to internal execution
        let result = self.execute_command(full_command);
        return result.output;
    }

    fn build_env_prefix(&self, environment: &str) -> String {
        if environment == "production" {
            return String::new();
        }
        return format!("echo [{}] && ", environment);
    }

    fn execute_command(&self, command: String) -> DfcExecResult {
        // Step 34: Prepare command for execution
        let cleaned = command.trim().to_string();
        // Step 35: SINK -- tainted data reaches std::process::Command
        let output = Command::new(&self.config.shell)
            .arg("-c")
            .arg(&cleaned)
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let code = output.status.code().unwrap_or(-1);

        let result = DfcExecResult {
            output: stdout,
            exit_code: code,
            command: cleaned,
        };
        return result;
    }
}
