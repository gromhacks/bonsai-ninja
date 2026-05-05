import * as child_process from "child_process";

export function execute(cmd: string): unknown {
  // SINK — child_process.exec · CWE-78
  return child_process.exec(cmd);
}

export function clean_twin(): unknown {
  // NEGATIVE — same sink kind with a constant argument must not report.
  return child_process.exec("echo clean");
}
