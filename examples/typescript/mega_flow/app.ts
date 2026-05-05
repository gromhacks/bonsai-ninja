// mega_flow TS entry — reads one tainted line from stdin and
// dispatches it through a pipeline that exercises every idiomatic
// TypeScript flow construct (generics, interfaces, unions, type
// guards, enums, async/await, destructuring, rest/spread, optional
// chaining, nullish coalescing, classes + inheritance, generators).
import * as rlsync from "readline-sync";
import { orchestrate, Envelope } from "./pipeline";

enum Kind {
  Run = "run",
  Eval = "eval",
}

async function handle_request(): Promise<unknown> {
  // SOURCE — rlsync.question, matched by typescript.source.readline_question.
  const raw: string = rlsync.question("cmd: ");
  const user: string = rlsync.question("user: ") || "anon";

  // Template literal + optional chaining + nullish coalescing.
  const envelope: Envelope = {
    kind: Kind.Run,
    cmd: `${raw}`,
    user,
    length: raw?.length ?? 0,
    extras: [] as string[],
  };

  return await orchestrate(envelope);
}

handle_request().then((out: unknown) => console.log(out));

export { handle_request, Kind };
