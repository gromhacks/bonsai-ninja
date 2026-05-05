declare module "readline-sync" {
  export function question(prompt: string): string;
}

declare module "child_process" {
  export function exec(command: string): unknown;
}
