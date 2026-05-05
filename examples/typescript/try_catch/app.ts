import { exec } from "child_process";

export function tainted_through_try(): void {
  let t: string;
  try {
    t = process.env.CMD!;
  } catch {
    t = "";
  }
  exec(t);
}
