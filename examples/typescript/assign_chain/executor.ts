import { exec } from "child_process";

export function runInOtherFile(cmd: string): void {
  // POSITIVE (cross-file)
  exec(cmd);
}
