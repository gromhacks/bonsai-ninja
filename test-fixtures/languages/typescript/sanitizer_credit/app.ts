import { exec } from "child_process";
import shellescape from "shell-escape";

export function unsanitized(): void {
  const t = process.env.CMD!;
  exec(t);
}

export function sanitized(): void {
  const t = process.env.CMD!;
  const safe = shellescape([t]);
  exec(safe);
}
