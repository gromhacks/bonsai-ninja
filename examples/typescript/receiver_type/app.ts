// Receiver-type audit fixture (TypeScript).
// child_process.exec(tainted) — module-namespace receiver.
import { exec } from "child_process";

export function handle(): void {
  // POSITIVE
  const tainted = process.env.CMD!;
  exec(tainted);
}
