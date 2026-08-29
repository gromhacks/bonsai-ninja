import { exec } from "child_process";

export function taint_one_leg(cond: boolean): void {
  let x: string;
  if (cond) { x = process.env.CMD!; }
  else { x = "safe-static"; }
  exec(x);
}

export function taint_overwritten(cond: boolean): void {
  let x = process.env.CMD!;
  if (cond) { x = "clean-then"; }
  else { x = "clean-else"; }
  exec(x);
}
