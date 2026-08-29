import { exec } from "child_process";

export function execute(cmd: string): void {
  // POSITIVE (terminal cross-file sink)
  exec(cmd);
}
