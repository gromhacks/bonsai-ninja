// language_gauntlet TS entry — reads one tainted Express query field and
// dispatches it through a pipeline that exercises every idiomatic
// TypeScript flow construct (generics, interfaces, unions, type
// guards, enums, async/await, destructuring, rest/spread, optional
// chaining, nullish coalescing, classes + inheritance, generators).
import express, { Request } from "express";
import { orchestrate, Envelope } from "../application/pipeline";

enum Kind {
  Run = "run",
  Eval = "eval",
}

async function handle_request(req: Request): Promise<unknown> {
  // SOURCE — Express query fields are remote HTTP input.
  const raw: string = String(req.query.cmd ?? "");
  const user: string = "remote";

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

const app = express();
app.get("/run", handle_request);

export { handle_request, Kind };
