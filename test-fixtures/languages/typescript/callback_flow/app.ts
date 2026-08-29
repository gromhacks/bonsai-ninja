import { exec } from "child_process";

function executor(cmd: string): void { exec(cmd); }
function run(cb: (s: string) => void, value: string): void { cb(value); }

export function pass_to_callback(): void {
  const t = process.env.CMD!;
  run(executor, t);
}
