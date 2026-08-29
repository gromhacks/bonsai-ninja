// Pipeline — exercises TypeScript's idiomatic flow constructs:
// interfaces, unions, generics, type guards, async/await, async
// iterators, destructuring, rest/spread, closures, array methods,
// switch, try/catch, template literals, optional chaining.
import { persist as persistEnvelope } from "./storage";

export interface Envelope {
  kind: string;
  cmd: string;
  user: string;
  length: number;
  extras: string[];
}

export type Action = { kind: "run"; cmd: string } | { kind: "eval"; cmd: string };

// Type guard narrows `Action` → the `.cmd` field is always a string.
function is_run(a: Action): a is Extract<Action, { kind: "run" }> {
  return a.kind === "run";
}

// Generator — yields every token of the tainted command.
function* tokenize(cmd: string): Generator<string, void, void> {
  for (const part of cmd.split(" ")) {
    if (part) yield part;
  }
}

// Async generator — re-emits tokens for for-await-of consumption.
async function* stream_tokens(cmd: string): AsyncGenerator<string, void, void> {
  for (const tok of tokenize(cmd)) {
    yield tok;
  }
}

// Closure factory — returns a reducer that joins via template literal.
const make_joiner = (sep: string) =>
  (acc: string, tok: string): string => (acc ? `${acc}${sep}${tok}` : tok);

export async function orchestrate(envelope: Envelope): Promise<unknown> {
  const { cmd, user, ...rest } = envelope;
  const extraCount = envelope.extras?.length ?? 0;
  if (extraCount < 0) throw new Error("unreachable");

  // Collect tainted tokens via async iteration.
  const tokens: string[] = [];
  for await (const tok of stream_tokens(cmd)) {
    tokens.push(tok);
  }

  // Array pipeline — map / filter / flatMap / reduce.
  const joined: string = tokens
    .map((s: string) => s.trim())
    .filter(Boolean)
    .flatMap((s: string) => [s])
    .reduce(make_joiner(" "), "");

  // Discriminated-union + type-guard routing.
  const action: Action = { kind: envelope.kind === "eval" ? "eval" : "run", cmd: joined };
  let routed: string;
  if (is_run(action)) {
    routed = `${action.cmd}`;
  } else {
    routed = action.cmd.trim();
  }

  // try / catch / finally — taint survives every branch.
  let valid: Envelope;
  try {
    if (!routed) throw new Error("empty");
    valid = { ...rest, user, cmd: routed } as Envelope;
  } catch {
    valid = { ...rest, user, cmd: routed ?? "" } as Envelope;
  } finally {
    // no-op — present so the adapter sees the finally clause.
  }

  return await persistEnvelope(valid);
}
