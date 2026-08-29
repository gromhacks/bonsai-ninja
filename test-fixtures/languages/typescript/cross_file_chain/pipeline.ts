import { transformAndForward } from "./transformer";

export function runPipeline(payload: string): void {
  const wrapped = "[" + payload + "]";
  transformAndForward(wrapped);
}
