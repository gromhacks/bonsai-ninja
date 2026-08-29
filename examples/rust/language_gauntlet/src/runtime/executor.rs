use std::process::Command;

pub fn execute(cmd: &str) -> String {
    // SINK — rust.cmdi.command_new with tainted cmd. Broken into
    // separate statements so the adapter reliably attributes the
    // Command::new call to this function rather than module scope.
    let mut c = Command::new("sh");
    c.arg("-c");
    c.arg(cmd);
    let _ = c.status();
    cmd.to_string()
}

pub fn clean_twin() -> String {
    // NEGATIVE — same sink kind with a constant argument must not report.
    let mut c = Command::new("sh");
    c.arg("-c");
    c.arg("echo clean");
    let _ = c.status();
    "clean".to_string()
}
