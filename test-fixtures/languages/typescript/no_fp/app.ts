// False-positive audit fixture (TypeScript).
import { exec } from "child_process";

const CONST_OK = "ls /tmp";

export function decoy(): void {
  const _unused = process.env.IGNORED;
  exec(CONST_OK);
}

export function unrelated_chain(): string {
  const a = "hello";
  return a.toUpperCase();
}
