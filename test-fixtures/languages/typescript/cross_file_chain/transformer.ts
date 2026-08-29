import { execute } from "./executor";

export function transformAndForward(value: string): void {
  const upper = value.toUpperCase();
  execute(upper);
}
