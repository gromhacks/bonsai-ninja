// language_gauntlet JS entry — reads an Express request query, then dispatches
// the tainted value through
// a pipeline that exercises every idiomatic JS flow construct
// (async/await, destructuring, rest/spread, closures, array methods,
// switch, template literals, optional chaining, classes, generators).
const express = require("express");
const { orchestrate } = require("../application/pipeline");

async function handle_request(req) {
  // SOURCE — Express query fields are remote HTTP input.
  const raw = req.query.cmd ?? "";
  const user = "remote";

  // Template literal + spread + optional chaining — taint rides
  // through the envelope's cmd field.
  const envelope = {
    kind: "run",
    cmd: `${raw}`,
    user,
    length: raw?.length ?? 0,
    extras: [],
  };

  return await orchestrate(envelope);
}

const app = express();
app.get("/run", handle_request);

module.exports = { handle_request };
