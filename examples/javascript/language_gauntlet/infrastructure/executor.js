// SINK — child_process.exec with attacker-controlled cmd.
const child_process = require("child_process");

function execute(cmd) {
  // js.cmdi.child_process_exec · severity=critical · CWE-78
  return child_process.exec(cmd);
}

function clean_twin() {
  // NEGATIVE — same sink kind with a constant argument must not report.
  return child_process.exec("echo clean");
}

module.exports = { execute, clean_twin };
