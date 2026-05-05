// Cross-file argument flow audit fixture (TypeScript).
import { runPipeline } from "./pipeline";

export function handler(): void {
  // POSITIVE
  const user = process.env.CMD!;
  runPipeline(user);
}

export function handlerSplit(): void {
  // POSITIVE
  const user = process.env.FROM!;
  const flag = process.env.FLAG!;
  runPipeline(user + ":" + flag);
}
